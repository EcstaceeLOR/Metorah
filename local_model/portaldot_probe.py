"""Read-only Portaldot JSON-RPC capability probe. NEVER submits transactions.

Run with a local portaldot_dev process or an organizer-confirmed public endpoint.
A successful connection alone does not prove WASM/EVM contract deployment works.
"""
import argparse
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path

try:
    from websockets.asyncio.client import connect
except ImportError:
    from websockets import connect


async def main(url: str, timeout: float, out: Path):
    result = {"mode":"read-only RPC probe", "timestamp_utc":datetime.now(timezone.utc).isoformat(),
              "endpoint":url, "reachable":False, "rpc":{}, "contract_deployed":False,
              "evm_deployed":False, "note":"RPC responses do not establish contract-deployment support"}
    try:
        async with asyncio.timeout(timeout * 10):
            async with connect(url, open_timeout=timeout, close_timeout=timeout, max_size=16*1024*1024) as socket:
                result['reachable']=True
                methods = ['system_chain','system_name','system_version','state_getRuntimeVersion',
                           'chain_getFinalizedHead','rpc_methods','eth_chainId']
                for idx,method in enumerate(methods,1):
                    try:
                        await socket.send(json.dumps({'jsonrpc':'2.0','method':method,'params':[],'id':idx}))
                        reply=json.loads(await asyncio.wait_for(socket.recv(), timeout))
                        if reply.get('id') != idx:
                            result['rpc'][method]={'error':'unexpected response id'}
                        elif 'error' in reply:
                            result['rpc'][method]={'error':reply['error']}
                        elif method=='rpc_methods':
                            supported=reply.get('result',{}).get('methods',[])
                            result['rpc'][method]={"method_count":len(supported),
                                "contracts_methods":[m for m in supported if 'contract' in m.lower()],
                                "eth_methods":[m for m in supported if m.startswith('eth_')]}
                        else:
                            result['rpc'][method]=reply.get('result')
                    except Exception as exc:
                        result['rpc'][method]={'error':str(exc)}
    except Exception as exc:
        result['connection_error']=f'{type(exc).__name__}: {exc}'
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result, indent=2)+'\n')
    print('Reachable:',result['reachable'])
    print('Chain:',result['rpc'].get('system_chain','not available'))
    print('Runtime:',result['rpc'].get('state_getRuntimeVersion','not available'))
    if not result['reachable']:
        print('Blocker:',result.get('connection_error'))
    print('Probe report:',out)
    return result

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--url',default='ws://127.0.0.1:9944')
    parser.add_argument('--timeout',type=float,default=3)
    parser.add_argument('--output',type=Path,default=Path(__file__).parent/'artifacts'/'portaldot-probe.json')
    args=parser.parse_args()
    asyncio.run(main(args.url,args.timeout,args.output))
