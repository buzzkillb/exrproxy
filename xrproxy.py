# Copyright (c) 2019-2020 The Blocknet developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#!/usr/bin/env python3

import bitcoin.core
import bitcoin.signmessage
import bitcoin.wallet
import json
import requests
import threading
import uwsgi

# import pydevd_pycharm
# pydevd_pycharm.settrace('localhost', port=4444, stdoutToServer=True, stderrToServer=True)


def application(env: dict, start_response):
    # Select chain
    chain = uwsgi.opt.get('BLOCKNET_CHAIN', b'mainnet').decode('utf8').strip()
    try:
        bitcoin.SelectParams(chain)
    except ValueError as e:
        print('Failed to parse BLOCKNET_CHAIN parameter, defaulting to mainnet: ' + getattr(e, 'message', repr(e)))
        bitcoin.SelectParams('mainnet')

    snodekey = bitcoin.wallet.CKey

    # check snode key
    snodekey_raw = uwsgi.opt.get('SERVICENODE_PRIVKEY', b'').decode('utf8').strip()
    if not snodekey_raw:
        return send_response({
            'code': 1002,
            'error': 'Internal Server Error: bad service node key'
        }, snodekey, start_response)

    try:
        snodekey = bitcoin.wallet.CBitcoinSecret(snodekey_raw)
    except bitcoin.wallet.CBitcoinSecretError as e:
        print(getattr(e, 'message', repr(e)))
        return send_response({
            'code': 1002,
            'error': 'Internal Server Error: bad service node key'
        }, snodekey, start_response)

    # parse the request path
    request_path = str(env.get('PATH_INFO'))
    paths = request_path.split('/')
    print('request_path: {}, paths: {}'.format(request_path,paths))
    if len(paths) > 1:
        del paths[0]

    if len(paths) < 2:
        return send_response({
            'code': 1004,
            'error': 'Bad request path ' + request_path + ' , The path must be in the format '
                                                          '/xr/BLOCK/xrGetBlockCount'
        }, snodekey, start_response)
    elif len(paths) > 3:
        return send_response({
            'code': 1004,
            'error': 'Bad request path ' + request_path + ' , The path must have a namespace, a method, '
                                                          'and a token, for example: /xr/BLOCK/xrGetBlockCount'
        }, snodekey, start_response)

    namesp = paths[0]
    token = ''
    xrfunc = ''
    if namesp == 'xr':
        token = paths[1]
        xrfunc = paths[2]
    elif namesp == 'xrs':
        xrfunc = paths[1]
    print('token: {} xrfunc: {}'.format(token,xrfunc))
    if not namesp or not xrfunc or (namesp == 'xr' and not token):
        return send_response({
            'code': 1004,
            'error': 'Bad request path ' + request_path + ' , The path must have a namespace, a method, '
                                                          'and a token, for example: /xr/BLOCK/xrGetBlockCount'
        }, snodekey, start_response)

    # if xrouter plugin, set token to xr func name
    if namesp == 'xrs':
        token = xrfunc
        #debug code
        token = xrfunc.split('_')[0]
        print('xrs namesp found, set token: {}'.format(token))

    # if payment tx exists, process it in background
    payment_tx = str(env.get('HTTP_XR_PAYMENT', ''))
    should_handle = uwsgi.opt.get('HANDLE_PAYMENTS', b'true').decode('utf8').lower()
    if should_handle == 'true' or should_handle == '1':
        payment_enforcement = uwsgi.opt.get('HANDLE_PAYMENTS_ENFORCE', b'false').decode('utf8').lower()
        cmd_enforce = uwsgi.opt.get('RPC_' + token + '_PAYMENTS_ENFORCE', b'false').decode('utf8').lower()
        if (cmd_enforce == 'true' or cmd_enforce == '1') and (payment_enforcement == 'true' or payment_enforcement == '1'):
            if payment_tx == '' or not handle_payment(payment_tx, env, token):
                return send_response({
                    'code': 1028,
                    'error': 'Bad request: bad or insufficient fee for ' + xrfunc + ' for token ' + token
                }, snodekey, start_response)
        else:
            hp_thread = threading.Thread(target=handle_payment, args=(payment_tx, env, token))
            hp_thread.start()

    try:
        print('call_xrfunc: {} env: {}'.format(xrfunc,env))
        response = call_xrfunc(namesp, token, xrfunc, env)
        return send_response(response, snodekey, start_response)
    except ValueError as e:
        print('value error: {}'.format(e))
        return send_response({
            'code': 1002,
            'error': 'Internal Server Error: valueerror: failed to call method ' + xrfunc + ' for token ' + token
                     + ' : ' + getattr(e, 'message', repr(e))
        }, snodekey, start_response)
    except:
        return send_response({
            'code': 1002,
            'error': 'Internal Server Error: sendresponse: failed to call method ' + xrfunc + ' for token ' + token
        }, snodekey, start_response)


def call_xrfunc(namesp: str, token: str, xrfunc: str, env: dict):
    is_xrouter_plugin = namesp == 'xrs'

    # obtain host info
    rpchost = uwsgi.opt.get('RPC_' + token + '_HOSTIP', b'').decode('utf8')
    rpcport = uwsgi.opt.get('RPC_' + token + '_PORT', b'').decode('utf8')
    rpcuser = uwsgi.opt.get('RPC_' + token + '_USER', b'').decode('utf8')
    rpcpass = uwsgi.opt.get('RPC_' + token + '_PASS', b'').decode('utf8')
    rpcver = uwsgi.opt.get('RPC_' + token + '_VER', b'1.0').decode('utf8')
    rpcmethod = uwsgi.opt.get('RPC_' + token + '_METHOD', b'').decode('utf8')
    #rpcmethod = ''
    print('rpcmethod: {}'.format(rpcmethod))

    try:
        request_body_size = int(env.get('CONTENT_LENGTH', 0))
    except ValueError:
        request_body_size = 0

    params = []
    print('checking request... xrfunc: {} env: {} token: {} namesp: {}'.format(xrfunc,env,token,namesp))
    if request_body_size > 0:
        request_body = env.get('wsgi.input').read(request_body_size)
        if request_body != b'\n':
            try:
                data = request_body.decode('utf8')
                print('request_body_data: {}'.format(data))
                print('org_params: {}'.format(params))
                #print('jsonloads_data: {}'.format(json.loads(data)))
                params = json.loads(data)
                print('params: {}'.format(params))
            except Exception as e:
                print('error_request_body: {}'.format(e))
                params = data
                pass

    if is_xrouter_plugin:
        if 'RPC_' + token + '_METHOD' in uwsgi.opt:
            print('setting rpc method')
            rpcmethod = uwsgi.opt.get('RPC_' + token + '_METHOD', b'').decode('utf8')
        elif 'URL_' + token + '_HOSTIP' in uwsgi.opt:
            print('call_url URL_ plugin: {}'.format(params))
            return call_url(xrfunc, params, env)

    if not rpchost or not rpcport or not rpcuser or not rpcpass or (is_xrouter_plugin and not rpcmethod):
        return {
            'code': 1002,
            'error': 'Internal Server Error: bad proxy configuration for token ' + token
        }

    # resolve the rpc name from the supplied xrouter call
    rpc_method = rpcmethod.lower() if is_xrouter_plugin else xr_to_rpc(token, xrfunc)
    if xrfunc[:3].lower() == 'eth':
        rpc_method = xrfunc
    
    if not rpc_method:
        return {
            'code': 1031,
            'error': 'Unsupported call ' + xrfunc + ' for token ' + token
        }

    rpcurl = 'http://' + rpcuser + ':' + rpcpass + '@' + rpchost + ':' + rpcport
    if rpcuser == '' and rpcpass == '':  # if no rpc credentials
        rpcurl = 'http://' + rpchost + ':' + rpcport
    headers = {'Content-Type': 'application/json'}
    
    l_xr_method = xrfunc if xrfunc[:3].lower() == 'eth' else xrfunc.lower()
    l_token = token.lower()
    print('xrfunc: {} token: {} l_xr_method: {}'.format(xrfunc,l_token,l_xr_method))

    if l_token == 'eth':
        print('token eth')
        if l_xr_method == 'xrdecoderawtransaction':
            pass
        if l_xr_method == 'xrgetblockcount':
            pass
        if l_xr_method == 'xrgetblockhash':
            if isinstance(params[0], int):
                params = [hex(params[0]), False]
            elif isinstance(params[0], str) and not params[0].startswith('0x'):
                try:  # first check if int
                    i = int(params[0])
                    params = [hex(i), False]
                except ValueError:
                    params = ['0x' + params[0], False]
            else:
                params = [params[0], False]
        if l_xr_method == 'xrgetblock':
            params = [params[0], False]
        if l_xr_method == 'xrgetblocks' or l_xr_method == 'xrgettransactions':  # iterate over all ids
            response = []
            for b_id in params:
                parsed_id: any
                rpc_method2 = rpc_method
                if isinstance(b_id, int):
                    parsed_id = hex(b_id)
                    if l_xr_method == 'xrgetblocks':
                        rpc_method2 = 'eth_getBlockByNumber'
                else:
                    parsed_id = b_id
                params2 = [parsed_id, False]
                if l_xr_method == 'xrgettransactions':
                    params2 = [parsed_id] # transactions doesn't support 2nd parameter
                payload = json.dumps({
                    'id': 1,
                    'method': rpc_method2,
                    'params': params2,
                    'jsonrpc': rpcver
                })
                try:
                    print('### requests_call_payload: {}'.format(payload))
                    res = requests.post(rpcurl, headers=headers, data=payload)
                    print('### postresults: {}'.format(res))
                    response += [parse_result(json.loads(res.content))]
                except Exception as e:
                    print('error: {} # requests_call'.format(e))
                    return {
                        'code': 1002,
                        'error': 'Internal Server Error: failed to connect to ' + xrfunc + ' for token ' + token
                    }
            print('returned response: {}'.format(response))
            return response
        if l_xr_method == 'xrgettransaction':
            pass
        if l_xr_method == 'xrsendtransaction':
            pass
        print('l_xr_debug: {}'.format(params))
        if l_xr_method or rpcmethod == 'passthrough':
        #if rpcmethod == 'passthrough':
            print('*** PASSTHROUGH ***')
            print('l_xr_method: {}  rpcmethod: {} params: {}'.format(l_xr_method, rpcmethod,params))
            payload = params
            if l_xr_method == 'eth_pass':
              payload = json.dumps({
                  'id': 1,
                  'method': rpcmethod,
                  'params': params,
                  #'params': {'jsonrpc': rpcver,
                  #           'method': l_xr_method,
                  #           'params':params,
                  #           'id':2},
                  'jsonrpc': rpcver
                  })
              print('updated_payload_eth_pass: {}'.format(payload))
              pass
            else:
              payload = json.dumps({
                  'id': 1,
                  'method': rpcmethod,
                  #'params': params,
                  'params': {'jsonrpc': rpcver,
                             'method': l_xr_method,
                             'params':params,
                             'id':1},
                  'jsonrpc': rpcver
                  })
              print('updated_payload_non_eth_pass: {}'.format(payload))
              pass
   
    elif l_token == 'neo':
        if l_xr_method == 'xrdecoderawtransaction':
            pass
        if l_xr_method == 'xrgetblockcount':
            pass
        if l_xr_method == 'xrgetblockhash':
            params[0] = int(params[0])
        if l_xr_method == 'xrgetblock':
            params = [params[0], 1]
        if l_xr_method == 'xrgetblocks' or l_xr_method == 'xrgettransactions': # iterate over all ids
            response = []
            for b_id in params:
                params2 = [b_id]
                if l_xr_method == 'xrgettransactions' or l_xr_method == 'xrgetblocks':
                    params2 += [1]
                payload = json.dumps({
                    'id': 1,
                    'method': rpc_method,
                    'params': params2,
                    'jsonrpc': rpcver
                })
                try:
                    print('requests: neo {}, {}'.format(rpcurl, payload))
                    res = requests.post(rpcurl, headers=headers, data=payload)
                    print('### postresults:: {}'.format(res))
                    response += [parse_result(json.loads(res.content))]
                except:
                    return {
                        'code': 1002,
                        'error': 'Internal Server Error: failed to connect to ' + xrfunc + ' for token ' + token
                    }
            print('returned response:: {}'.format(response))
            return response
        if l_xr_method == 'xrgettransaction':
            params = [params[0], 1]
        if l_xr_method == 'xrsendtransaction':
            pass
    else:
        if l_xr_method == 'xrdecoderawtransaction':
            pass
        if l_xr_method == 'xrgetblockcount':
            pass
        if l_xr_method == 'xrgetblockhash':
            params[0] = int(params[0])
        if l_xr_method == 'xrgetblock':
            pass
        if l_xr_method == 'xrgetblocks' or l_xr_method == 'xrgettransactions': # iterate over all ids
            response = []
            for b_id in params:
                params2 = [b_id]
                if l_xr_method == 'xrgettransactions':
                    params2 += [1]
                payload = json.dumps({
                    'id': 1,
                    'method': rpc_method,
                    'params': params2,
                    'jsonrpc': rpcver
                })
                try:
                    print('requests posts: {} {}'.format(rpcurl, payload))
                    res = requests.post(rpcurl, headers=headers, data=payload)
                    print('### postresults: {}'.format(res))
                    response += [parse_result(json.loads(res.content))]
                except:
                    return {
                        'code': 1002,
                        'error': 'Internal Server Error: failed to connect to ' + xrfunc + ' for token ' + token
                    }
            print('returned response::: {}'.format(response))
            return response
        if l_xr_method == 'xrgettransaction':
            params = [params[0], 1]
        if l_xr_method == 'xrsendtransaction':
            pass

        #if params['method'] == 'eth_pass':
        if params['method'] == 'eth_test':
            print('### eth_call ###')
            payload = params
            payload = json.dumps({
                'id': 1,
                'method': 'passthrough',
                'params': params,
                'jsonrpc': rpcver
                })

        else:
            print('### payload set ###')
            payload = json.dumps({
                'id': 1,
                'method': rpc_method,
                'params': params,
                'jsonrpc': rpcver
                })


    print('request_post_check - payload: {}'.format(payload))
    try:
        print('requests_post: {}'.format(payload))
        res = requests.post(rpcurl, headers=headers, data=payload)
        print('responce_data: {}'.format(res.content))
        try:
            #response = parse_result(json.loads(res.content))
            response = json.loads(res.content)    # response should match infura format
            print('returned response:::: {}'.format(response))
            return response
        except ValueError as e:
            print('valueerror: {}'.format(e))
            return res.content.decode('utf8')  # return raw string if json decode fails
    except Exception as e:
        print('exception: {}'.format(e))
        return {
            'code': 1002,
            'error': 'Internal Server Error: failed to connect to ' + xrfunc + ' for token ' + token
        }


def call_url(xrfunc: str, params: any, env: dict):
    rpchost = uwsgi.opt.get('URL_' + xrfunc + '_HOSTIP', b'').decode('utf8')
    rpcport = uwsgi.opt.get('URL_' + xrfunc + '_PORT', b'').decode('utf8')
    rpcurl = 'http://' + rpchost + ':' + rpcport + str(env.get('PATH_INFO', b''))

    headers = {
        'Content-Type': 'application/json',
        'XR-Pubkey': str(env.get('HTTP_XR_PUBKEY', b'')),
        'XR-Signature': str(env.get('HTTP_XR_SIGNATURE', b'')),
        'XR-Payment': str(env.get('HTTP_XR_PAYMENT', b'')),
    }
    payload = '' if len(params) == 0 else json.dumps(params)

    try:
        res = requests.post(rpcurl, headers=headers, data=payload)
        try:
            response = json.loads(res.content)
            return parse_result(response)
        except:
            return res.content.decode('utf8')
    except:
        return {
            'code': 1002,
            'error': 'Internal Server Error: failed to connect to ' + xrfunc
        }


def handle_payment(payment_tx: str, env: dict, token: str):
    override = uwsgi.opt.get('RPC_' + token + '_PAYMENT_OVERRIDE', b'false').decode('utf8')
    print('Handling payment for token: {} Payment Override: {}'.format(token, override))

    if override == 'true' or override == '1':
        rpchost = uwsgi.opt.get('RPC_' + token + '_PAYMENT_HOSTIP', b'').decode('utf8')
        rpcport = uwsgi.opt.get('RPC_' + token + '_PAYMENT_PORT', b'').decode('utf8')
        rpcuser = uwsgi.opt.get('RPC_' + token + '_PAYMENT_USER', b'').decode('utf8')
        rpcpass = uwsgi.opt.get('RPC_' + token + '_PAYMENT_PASS', b'').decode('utf8')
        rpcver = uwsgi.opt.get('RPC_' + token + '_PAYMENT_VER', b'1.0').decode('utf8')
    else:
        rpchost = uwsgi.opt.get('HANDLE_PAYMENTS_RPC_HOSTIP', b'').decode('utf8')
        rpcport = uwsgi.opt.get('HANDLE_PAYMENTS_RPC_PORT', b'').decode('utf8')
        rpcuser = uwsgi.opt.get('HANDLE_PAYMENTS_RPC_USER', b'').decode('utf8')
        rpcpass = uwsgi.opt.get('HANDLE_PAYMENTS_RPC_PASS', b'').decode('utf8')
        rpcver = uwsgi.opt.get('HANDLE_PAYMENTS_RPC_VER', b'1.0').decode('utf8')

    rpcurl = 'http://' + rpcuser + ':' + rpcpass + '@' + rpchost + ':' + rpcport
    if rpcuser == '' and rpcpass == '':  # if no rpc credentials
        rpcurl = 'http://' + rpchost + ':' + rpcport

    print('Sending request to: {}'.format(rpcurl))

    # client pubkey
    client_pubkey = str(env.get('HTTP_XR_PUBKEY', b''))

    params = [payment_tx]
    headers = {'Content-Type': 'application/json'}
    payload = json.dumps({
        'id': 1,
        'method': 'sendrawtransaction',
        'params': params,
        'jsonrpc': rpcver
    })

    try:
        res = requests.post(rpcurl, headers=headers, data=payload)
        enforce = uwsgi.opt.get('HANDLE_PAYMENTS_ENFORCE', b'false').decode('utf8')
        token_enforce = uwsgi.opt.get('RPC_' + token + '_PAYMENTS_ENFORCE', b'false').decode('utf8')

        # look for valid tx hash in response otherwise fail the check
        if (enforce == 'true' or enforce == '1') and (token_enforce == 'true' or token_enforce == '1'):
            payment_response = res.content.decode('utf8')
            json_response = res.json()

            cond = (
                'result' not in json_response
                or
                'error' in json_response and json_response['error'] is not None
                or
                'result' in json_response and len(json_response['result']) != 64
            )

            if cond:
                print('Failed to process payment from client: ' + client_pubkey
                      + 'Error: ' + payment_response + ' tx hex: ' + payment_tx)
                return False
        elif token_enforce == 'false' or token_enforce == '0':
            return True
        
        print('Successfully processed payment from client: ' + client_pubkey + ' BLOCK tx: ' + payment_tx)
        return True
    except:
        print('Failed to process payment from client: ' + client_pubkey + ' BLOCK tx: ' + payment_tx)
        return False


def parse_result(res: any):
    if 'result' in res and res['result']:
        return res['result']
    else:
        return res


def xr_to_rpc(token: str, xr_func: str):
    l_xr_method = xr_func.lower()
    l_token = token.lower()

    if l_token == 'eth':
        if l_xr_method == 'xrdecoderawtransaction': return ''
        if l_xr_method == 'xrgetblockcount': return 'eth_blockNumber'
        if l_xr_method == 'xrgetblockhash': return 'eth_getBlockByNumber'
        if l_xr_method == 'xrgetblock': return 'eth_getBlockByHash'
        if l_xr_method == 'xrgetblocks': return 'eth_getBlockByHash'
        if l_xr_method == 'xrgettransaction': return 'eth_getTransactionByHash'
        if l_xr_method == 'xrgettransactions': return 'eth_getTransactionByHash'
        if l_xr_method == 'xrsendtransaction': return 'eth_sendRawTransaction'
    elif l_token == 'neo':
        if l_xr_method == 'xrdecoderawtransaction': return ''
        if l_xr_method == 'xrgetblockcount': return 'getblockcount'
        if l_xr_method == 'xrgetblockhash': return 'getblockhash'
        if l_xr_method == 'xrgetblock': return 'getblock'
        if l_xr_method == 'xrgetblocks': return 'getblock'
        if l_xr_method == 'xrgettransaction': return 'getrawtransaction'
        if l_xr_method == 'xrgettransactions': return 'getrawtransaction'
        if l_xr_method == 'xrsendtransaction': return 'sendrawtransaction'
    else:
        if l_xr_method == 'xrdecoderawtransaction': return 'decoderawtransaction'
        if l_xr_method == 'xrgetblockcount': return 'getblockcount'
        if l_xr_method == 'xrgetblockhash': return 'getblockhash'
        if l_xr_method == 'xrgetblock': return 'getblock'
        if l_xr_method == 'xrgetblocks': return 'getblock'
        if l_xr_method == 'xrgettransaction': return 'getrawtransaction'
        if l_xr_method == 'xrgettransactions': return 'getrawtransaction'
        if l_xr_method == 'xrsendtransaction': return 'sendrawtransaction'

    return ''


def send_response(result: any, snodekey: bitcoin.wallet.CKey, start_response):
    headers = [('Content-Type', 'application/json')]
    res_data = result.encode('utf8') if isinstance(result, str) else json.dumps(result).encode('utf8')

    # sign the result data if the servicenode key is valid
    try:
        res_hash = bitcoin.core.Hash(bitcoin.core.serialize.BytesSerializer.serialize(res_data))
        sig, i = snodekey.sign_compact(res_hash)
        meta = 27 + i
        if snodekey.is_compressed:
            meta += 4
        headers += [('XR-Pubkey', snodekey.pub.hex()),
                    ('XR-Signature', bitcoin.core.b2x(bitcoin.signmessage._bchr(meta) + sig))]
    except Exception as e:
        print('Unknown signing error: ' + getattr(e, 'message', repr(e)))

    start_response('200 OK', headers)
    return res_data
