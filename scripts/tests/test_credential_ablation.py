import copy
from dataclasses import replace
import pytest
from rq3.dct_vs_jwt import (fixture, run_sequence, CredentialVerifier,
                            RevocationRegistry, SCENARIOS)


@pytest.mark.parametrize('variant', ['B3', 'B4'])
@pytest.mark.parametrize('scenario', SCENARIOS)
def test_ablation_outcomes_and_recovery(variant, scenario):
    row = run_sequence(0, scenario, variant, fixture(0))
    for record in row['records']:
        if record['kind'] == 'legitimate':
            assert record['accepted']
        else:
            should_reject = variant == 'B4' or scenario in (
                'cross_container', 'post_revocation', 'credential_tamper')
            assert record['accepted'] == (not should_reject)
            if should_reject:
                assert record['state_before'] == record['state_after']
    if scenario == 'event_tamper' and variant == 'B4':
        assert row['records'][2]['reason'] == 'event does not match authenticated chain'
    if scenario == 'signature_tamper' and variant == 'B4':
        assert row['records'][2]['reason'] == 'invalid signature'


@pytest.mark.parametrize('kind', ['missing', 'wrong_identity', 'gap', 'seq_rewrite', 'foreign_chain'])
def test_fail_closed_then_original_chain_recovers(kind):
    ctx, signer, key, token, pairs = fixture(0)
    v = CredentialVerifier('B4', ctx, signer, key, RevocationRegistry())
    bad_token, bad_ctx, pair = copy.deepcopy(token), ctx, pairs[0]
    if kind == 'missing': pair = (None, None)
    elif kind == 'wrong_identity': bad_ctx = replace(ctx, did='other')
    elif kind == 'gap': pair = pairs[1]
    elif kind == 'seq_rewrite': pair = (pairs[1][0], replace(pairs[1][1], seq=0))
    elif kind == 'foreign_chain': pair = fixture(1)[4][0]
    before = v.snapshot()
    assert not v.verify(bad_token, bad_ctx, *pair)[0]
    assert before == v.snapshot()
    for pair in pairs:
        assert v.verify(token, ctx, *pair)[0]
