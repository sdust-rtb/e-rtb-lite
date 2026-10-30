"""Independently check saved B4 signatures/chain transitions without core imports.

Credential-envelope checks are exercised by tests and rerun, not independently
authenticated here (the experimental issuer HMAC secret is intentionally absent).
"""
import hashlib
import hmac
import json
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


def verify(directory):
    directory = Path(directory)
    metadata = json.loads((directory / 'metadata.json').read_text())
    raw = directory / 'trials.jsonl'
    assert hashlib.sha256(raw.read_bytes()).hexdigest() == metadata['raw_sha256']
    root = Path(__file__).resolve().parents[1]
    for name, digest in metadata['source_sha256'].items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest, name
    rows = [json.loads(line) for line in raw.read_text().splitlines()]
    checked = 0
    for row in rows:
        if row['variant'] != 'B4':
            continue
        head, seq = bytes.fromhex(row['anchor']), 0
        public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(row['public_key']))
        for r in row['records']:
            assert r['state_before'] == {'next_seq': seq, 'head': head.hex()}
            p, e = r['package'], r['event']
            seq_ok = p['seq'] == seq
            signed = (b'ERTB-EVIDENCE-v2\x00' + bytes.fromhex(p['h_curr'])
                      + p['seq'].to_bytes(8, 'big') + int(p['timestamp']).to_bytes(8, 'big'))
            try:
                public.verify(bytes.fromhex(p['sigma']), signed)
                sig_ok = True
            except InvalidSignature:
                sig_ok = False
            encoded = json.dumps(['ERTB-EVENT-v2', e['syscall_type'], e['target_resource'],
                                  e['parameters'], e['timestamp_ns']], ensure_ascii=False,
                                 separators=(',', ':')).encode()
            chain_ok = hmac.new(head, encoded + p['seq'].to_bytes(8, 'big'), hashlib.sha256).hexdigest() == p['h_curr']
            if r['kind'] == 'legitimate':
                assert r['accepted'] and seq_ok and sig_ok and chain_ok
            elif row['scenario'] == 'replay':
                assert not r['accepted'] and not seq_ok and sig_ok
            elif row['scenario'] == 'event_tamper':
                assert not r['accepted'] and seq_ok and sig_ok and not chain_ok
            elif row['scenario'] == 'signature_tamper':
                assert not r['accepted'] and seq_ok and not sig_ok
            if r['accepted']:
                head, seq = bytes.fromhex(p['h_curr']), seq + 1
            assert r['state_after'] == {'next_seq': seq, 'head': head.hex()}
            checked += 1
    # Recount stored summary without importing the experiment runner.
    summary = json.loads((directory / 'summary.json').read_text())
    for cell in summary:
        group = [r for r in rows if r['variant'] == cell['variant'] and r['scenario'] == cell['scenario']]
        records = [r for row in group for r in row['records']]
        good = [r for r in records if r['kind'] == 'legitimate']
        attack = [r for r in records if r['kind'] == 'attack']
        assert cell['sequences'] == len(group)
        assert cell['legitimate_total'] == len(good)
        assert cell['legitimate_accepted'] == sum(r['accepted'] for r in good)
        assert cell['attack_total'] == len(attack)
        assert cell['attack_rejected'] == sum(not r['accepted'] for r in attack)
        assert cell['rejected_state_unchanged'] == all(r['state_before'] == r['state_after'] for r in records if not r['accepted'])
    result = {'verified': True, 'rows': len(rows), 'b4_records_independently_checked': checked,
              'raw_sha256': metadata['raw_sha256'], 'source_hashes_match': True,
              'summary_recount_matches': True,
              'scope': 'Saved B4 signature/chain/state checks; credential HMAC checks rely on tests/rerun'}
    (directory / 'verification.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    verify(sys.argv[1])
