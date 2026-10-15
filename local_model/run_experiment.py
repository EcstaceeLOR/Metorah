"""Run demonstrative Metorah offline experiment and save evidence JSON."""
from __future__ import annotations
from copy import deepcopy
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from metorah import (SourceLedger, TargetLedger, MigrationError, make_manifest,
                        verify_snapshot, proof_for, binding_payload, root_for)

ROOT = Path(__file__).parent


def demo_key(name: str):
    # DETERMINISTIC DEMO-ONLY keys. Never use them to secure real funds.
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f"statelift:demo-only:{name}".encode()).digest())


def pubhex(priv):
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()


def expect_rejected(name, call, checks):
    try:
        call()
    except MigrationError as exc:
        checks.append({"test": name, "status": "PASS", "reason": str(exc)})
        return
    raise AssertionError(f"attack unexpectedly succeeded: {name}")


def main():
    accounts = {name: demo_key('source:' + name) for name in ['Alice','Bob','Charlie','Diana','Eve']}
    destinations = {name: demo_key('destination:' + name) for name in accounts}
    amounts = {'Alice':400,'Bob':250,'Charlie':200,'Diana':100,'Eve':50}
    source = SourceLedger('simulated:portaldot-source-genesis', 'simulated:source-ledger-v1',
                          {pubhex(accounts[n]): u for n,u in amounts.items()})
    checks=[]
    # A successful transfer before freezing validates the source allows mutations.
    source.transfer(pubhex(accounts['Alice']), pubhex(accounts['Bob']), 10)
    amounts['Alice'] -= 10
    amounts['Bob'] += 10
    checks.append({'test': 'before freeze: valid balance transfer', 'status': 'PASS'})
    frozen = source.freeze()
    expect_rejected('after freeze: source transfer blocked',
                    lambda: source.transfer(pubhex(accounts['Bob']),pubhex(accounts['Eve']),3), checks)
    expect_rejected('after freeze: repeated freeze blocked', lambda: source.freeze(), checks)
    manifest = make_manifest(frozen, 'simulated:destination-genesis', 'simulated:destination-claim-v1')
    verified = verify_snapshot(source,frozen,manifest)
    target = TargetLedger(verified, 'simulated:destination-genesis', 'simulated:destination-claim-v1')
    checks.append({'test': 'snapshot independently matches frozen enumerable ledger', 'status': 'PASS'})

    tampered = deepcopy(manifest)
    for x in tampered['entries']:
        if x['source_pubkey'] == pubhex(accounts['Alice']):
            x['units'] += 200
    tampered['root'] = root_for(tampered['entries'])
    tampered['total'] += 200
    expect_rejected('tampered balances even with rehashed root rejected',
                    lambda: verify_snapshot(source, frozen, tampered), checks)

    omitted = deepcopy(manifest)
    omitted['entries'] = [e for e in omitted['entries'] if e['source_pubkey'] != pubhex(accounts['Diana'])]
    omitted['root'] = root_for(omitted['entries'])
    omitted['total'] = sum(e['units'] for e in omitted['entries'])
    expect_rejected('omitted user with rehashed root detected',
                    lambda: verify_snapshot(source, frozen, omitted), checks)

    def data_for(name):
        idx = next(i for i,e in enumerate(manifest['entries']) if e['source_pubkey'] == pubhex(accounts[name]))
        return manifest['entries'][idx], proof_for(manifest['entries'],idx)

    aentry, aproof=data_for('Alice')
    dest=pubhex(destinations['Alice'])
    message=binding_payload(verified.migration_id,verified.root,aentry['source_pubkey'],dest,aentry['units'])
    signed=accounts['Alice'].sign(message).hex()

    # Mallory cannot sign Alice's entitlement.
    mallory_sig=demo_key('attacker:Mallory').sign(message).hex()
    expect_rejected('third-party account theft blocked',
                    lambda: target.claim(aentry,aproof,dest,mallory_sig), checks)

    # A signature to one destination cannot authorize redirection.
    bad_dest=pubhex(demo_key('attacker:redirection'))
    expect_rejected('destination redirection blocked',
                    lambda: target.claim(aentry,aproof,bad_dest,signed), checks)

    # Tampered leaf cannot reuse honest leaf proof.
    bad_entry=deepcopy(aentry)
    bad_entry['units']+=50
    expect_rejected('tampered claim with authentic proof blocked',
                    lambda: target.claim(bad_entry,aproof,dest,signed), checks)

    # Successful claim is exactly once.
    target.claim(aentry,aproof,dest,signed)
    checks.append({'test': 'legitimate Alice claim accepted', 'status':'PASS'})
    expect_rejected('duplicate Alice claim rejected',
                    lambda: target.claim(aentry,aproof,dest,signed), checks)

    # Replay a claim under another source/destination domain.
    wrong_source=deepcopy(aentry)
    wrong_source['migration_id']='0'*64
    expect_rejected('cross-migration replay rejected',
                    lambda: target.claim(wrong_source,aproof,dest,signed),checks)

    # Wrong chain or claim-contract ID cannot instantiate this verified manifest.
    expect_rejected('wrong destination contract rejected',
                    lambda: TargetLedger(verified, verified.target_genesis,'simulated:attacker-contract'),checks)

    # Everyone claims; no balances lost or created. Destination ownership requires a
    # source Ed25519 signature and is NOT EVM account binding.
    for name in ['Bob','Charlie','Diana','Eve']:
        entry,proof=data_for(name)
        new_dest=pubhex(destinations[name])
        sig=accounts[name].sign(binding_payload(verified.migration_id,verified.root,
                                               entry['source_pubkey'],new_dest,entry['units'])).hex()
        target.claim(entry,proof,new_dest,sig)
    checks.append({'test': 'all remaining legitimate claims accepted','status':'PASS'})

    assert sum(source.balances.values())==1000
    assert manifest['total']==1000
    assert target.claimed_total==1000
    assert target.unclaimed_total==0
    assert len(target.claimed_source)==5
    assert len(target.claim_events)==5
    assert all(target.balances[pubhex(destinations[name])]==amounts[name] for name in amounts)
    checks.append({'test': 'source and destination value conservation verified','status':'PASS'})
    checks.append({'test': 'five unique claims, exactly matching expected balances','status':'PASS'})

    sample = {"source": {name: amounts[name] for name in amounts},
              "target": {name: target.balances[pubhex(destinations[name])] for name in amounts},
              "source_frozen": source.frozen,
              "source_total": source.balances and sum(source.balances.values()),
              "claimed_total": target.claimed_total,
              "unclaimed_total": target.unclaimed_total}
    report = {
        'experiment': 'Metorah Genesis — offline logical feasibility',
        'recorded_at_utc': datetime.now(timezone.utc).isoformat(),
        'mode': 'OFFLINE-SIMULATION; NOT PORTALDOT; NOT EVM; NOT ON-CHAIN',
        'portaldot_node_started': False,
        'portaldot_contract_deployed': False,
        'source_state_authenticated_by_trusted_chain_header': False,
        'assumptions': ['source ledger is fully enumerable and trusted',
                        'source supports a permanent freeze',
                        'local Ed25519 public keys stand in for wallet identities',
                        'destination is a Python logical model, not a smart contract',
                        'entitlement snapshot is independently checked against full source state'],
        'source_simulated_state_hash': frozen.simulated_state_hash,
        'source_simulated_block_number': frozen.simulated_block_number,
        'merkle_root': manifest['root'],
        'migration_id': verified.migration_id,
        'totals': sample,
        'checks': checks,
        'check_count': len(checks),
        'passes': sum(c['status']=='PASS' for c in checks),
        'failures': [c for c in checks if c['status']!='PASS'],
        'remaining_blockers': [
            'Run Portaldot development node and deploy genuine freezeable WASM source contract',
            'Authenticate enumerated source state with genuine finalized on-chain storage evidence',
            'Deploy and test destination claims on a confirmed qualifying Portaldot V3 environment',
            'Prove safe cutover and old-state retirement on-chain, not just in Python',
            'Map Substrate AccountId32 to EVM H160 using appropriate ownership proofs if cross-VM'
        ]
    }
    (ROOT/'artifacts'/'snapshot.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (ROOT/'artifacts'/'experiment-report.json').write_text(json.dumps(report,indent=2)+'\n')
    (ROOT/'artifacts'/'claims.json').write_text(json.dumps(target.claim_events,indent=2)+'\n')
    print(f"{report['passes']}/{report['check_count']} experiment checks passed")
    print('Mode:', report['mode'])
    print('Starting source total:',sum(source.balances.values()))
    print('Destination claimed total:',target.claimed_total)
    print('Unclaimed:',target.unclaimed_total)
    print('Merkle root:',manifest['root'])
    return report

if __name__=='__main__':
    main()
