"""Independent randomized and negative tests for the Metorah local model."""
import hashlib
import random
import unittest
from copy import deepcopy
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from metorah import (SourceLedger, TargetLedger, FrozenState, MigrationError, make_manifest,
                        verify_snapshot, proof_for, root_for, verify_proof, binding_payload)


def key(name):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(('DEMO-ONLY:'+name).encode()).digest())

def pub(priv):
    return priv.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                          format=serialization.PublicFormat.Raw).hex()

class TestMetorah(unittest.TestCase):
    def setUp(self):
        self.owners=[key('owner'+str(i)) for i in range(7)]
        self.keys=[pub(x) for x in self.owners]
        self.src=SourceLedger('sim:genesis-src','sim:ledger',dict(zip(self.keys,[17,29,31,7,3,113,1])))

    def prepared(self):
        frozen=self.src.freeze()
        manifest=make_manifest(frozen,'sim:genesis-dst','sim:claim')
        verification=verify_snapshot(self.src,frozen,manifest)
        target=TargetLedger(verification,'sim:genesis-dst','sim:claim')
        return frozen,manifest,target

    def test_total_invariant_on_random_transfers(self):
        rng=random.Random(0x51A7E)
        initial=sum(self.src.balances.values())
        for _ in range(350):
            sender=rng.choice(self.keys)
            receiver=rng.choice(self.keys)
            if sender==receiver:continue
            max_send=self.src.balances[sender]
            if max_send==0:continue
            amt=rng.randrange(1,max_send+1)
            self.src.transfer(sender,receiver,amt)
            self.assertEqual(sum(self.src.balances.values()),initial)

    def test_freeze_blocks_all_mutations(self):
        self.prepared()
        before=self.src.balances.copy()
        for a in self.keys:
            with self.assertRaises(MigrationError):self.src.transfer(a,self.keys[-1],1)
        self.assertEqual(self.src.balances,before)

    def test_snapshot_rejects_omitted_account_even_when_root_recomputed(self):
        frozen,manifest,_=self.prepared()
        fake=deepcopy(manifest)
        fake['entries']=fake['entries'][:-1]
        fake['root']=root_for(fake['entries'])
        fake['total']=sum(e['units'] for e in fake['entries'])
        with self.assertRaises(MigrationError):verify_snapshot(self.src,frozen,fake)

    def test_snapshot_rejects_changed_balance_even_with_rehashed_root(self):
        frozen,manifest,_=self.prepared()
        fake=deepcopy(manifest)
        fake['entries'][0]['units'] += 1
        fake['root']=root_for(fake['entries'])
        fake['total'] += 1
        with self.assertRaises(MigrationError):verify_snapshot(self.src,frozen,fake)

    def test_snapshot_rejects_duplicate_account(self):
        frozen,manifest,_=self.prepared()
        fake=deepcopy(manifest)
        fake['entries'][1]['source_pubkey']=fake['entries'][0]['source_pubkey']
        fake['root']=root_for(fake['entries'])
        with self.assertRaises(MigrationError):verify_snapshot(self.src,frozen,fake)

    def test_snapshot_rejects_nonfinalized_later_changes(self):
        frozen,manifest,_=self.prepared()
        # Malicious test override; not available in the contract API.
        self.src.balances[self.keys[0]] += 3
        with self.assertRaises(MigrationError):verify_snapshot(self.src,frozen,manifest)

    def test_all_merkle_proofs_and_tampering(self):
        _,manifest,_=self.prepared()
        for i,e in enumerate(manifest['entries']):
            proof=proof_for(manifest['entries'],i)
            self.assertTrue(verify_proof(e,proof,manifest['root']))
            fake=deepcopy(e);fake['units']+=1
            self.assertFalse(verify_proof(fake,proof,manifest['root']))
            if proof:
                broken=deepcopy(proof);broken[0]['hash']='00'*32
                self.assertFalse(verify_proof(e,broken,manifest['root']))

    def test_all_claims_conserve_supply(self):
        _,m,t=self.prepared()
        for i,e in enumerate(m['entries']):
            signer=next(o for o in self.owners if pub(o)==e['source_pubkey'])
            dst=pub(key('dest'+str(i)))
            signature=signer.sign(binding_payload(m['migration_id'],m['root'],e['source_pubkey'],dst,e['units'])).hex()
            t.claim(e,proof_for(m['entries'],i),dst,signature)
        self.assertEqual(t.claimed_total,m['total'])
        self.assertEqual(t.unclaimed_total,0)
        self.assertEqual(len(t.claimed_source),len(m['entries']))

    def test_claim_rejects_signer_theft_without_partial_state(self):
        _,m,t=self.prepared()
        e=m['entries'][0];p=proof_for(m['entries'],0)
        dst=pub(key('thief-dest'))
        msg=binding_payload(m['migration_id'],m['root'],e['source_pubkey'],dst,e['units'])
        sig=key('thief').sign(msg).hex()
        with self.assertRaises(MigrationError): t.claim(e,p,dst,sig)
        self.assertEqual(t.claimed_total,0)
        self.assertEqual(t.balances,{})
        self.assertEqual(len(t.claimed_source),0)

    def test_claim_rejects_redirection_and_replay(self):
        _,m,t=self.prepared()
        e=m['entries'][0];p=proof_for(m['entries'],0)
        signer=next(x for x in self.owners if pub(x)==e['source_pubkey'])
        d1=pub(key('safe-dest'))
        d2=pub(key('bad-dest'))
        sig=signer.sign(binding_payload(m['migration_id'],m['root'],e['source_pubkey'],d1,e['units'])).hex()
        with self.assertRaises(MigrationError):t.claim(e,p,d2,sig)
        self.assertEqual(t.claimed_total,0)
        t.claim(e,p,d1,sig)
        with self.assertRaises(MigrationError):t.claim(e,p,d1,sig)
        self.assertEqual(t.claimed_total,e['units'])

    def test_cross_migration_replay(self):
        _,m,t=self.prepared()
        e=deepcopy(m['entries'][0]);e['migration_id']='ab'*32
        with self.assertRaises(MigrationError):t.claim(e,proof_for(m['entries'],0),pub(key('other')),'00'*64)

    def test_no_claim_before_validated_freeze(self):
        fake = FrozenState(self.src.genesis, self.src.contract, self.src.height, "00" * 32, self.src.balances.copy())
        with self.assertRaises(MigrationError): verify_snapshot(self.src, fake, {})


    def test_zero_balance_account_is_not_migrated_as_entitlement(self):
        self.src.transfer(self.keys[0], self.keys[1], 17)
        self.assertEqual(self.src.balances[self.keys[0]], 0)
        frozen, manifest, target = self.prepared()
        self.assertEqual(len(manifest['entries']), 6)
        self.assertEqual(manifest['total'], sum(self.src.balances.values()))
        self.assertFalse(any(e['source_pubkey'] == self.keys[0] for e in manifest['entries']))

    def test_invalid_merkle_path_rejected(self):
        _, manifest, target = self.prepared()
        entry = manifest['entries'][0]
        bad_proof = proof_for(manifest['entries'], 0) + [{'side': 'invalid', 'hash': '00'*32}]
        self.assertFalse(verify_proof(entry, bad_proof, manifest['root']))

    def test_rejected_claim_never_changes_target_balance(self):
        _, m, t = self.prepared()
        e = deepcopy(m['entries'][0])
        e['units'] += 123
        with self.assertRaises(MigrationError):
            t.claim(e, proof_for(m['entries'], 0), pub(key('destination:malicious')), '00'*64)
        self.assertEqual(t.balances, {})
        self.assertEqual(t.claimed_total, 0)
        self.assertEqual(t.claim_events, [])

    def test_randomized_migrations(self):
        rng=random.Random(20261015)
        for run in range(60):
            owners=[key(f'random:{run}:{i}') for i in range(rng.randrange(1,15))]
            entries={pub(o):rng.randrange(1,100000) for o in owners}
            src=SourceLedger('sim:source:'+str(run),'sim:contract',entries)
            frozen=src.freeze()
            m=make_manifest(frozen,'sim:target:'+str(run),'sim:claim')
            checked=verify_snapshot(src,frozen,m)
            dst=TargetLedger(checked,checked.target_genesis,checked.target_contract)
            for i,e in enumerate(m['entries']):
                signer=next(o for o in owners if pub(o)==e['source_pubkey'])
                dest=pub(key(f'dest:{run}:{i}'))
                sig=signer.sign(binding_payload(m['migration_id'],m['root'],e['source_pubkey'],dest,e['units'])).hex()
                dst.claim(e,proof_for(m['entries'],i),dest,sig)
            self.assertEqual(dst.claimed_total,sum(entries.values()))
            self.assertEqual(dst.unclaimed_total,0)

if __name__=='__main__':unittest.main(verbosity=2)
