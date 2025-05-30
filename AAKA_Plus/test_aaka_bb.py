import pytest
from aaka_bb import AAKA_BB
from utils import setup
import crypto
from ecies.utils import generate_key

@pytest.fixture
def bb_instance():
    k = crypto.getKey()
    secp_k = generate_key()
    sk_bb = secp_k.secret
    pk_bb = secp_k.public_key.format(True)
    sqn_bb = 100
    param = setup(3)
    return AAKA_BB(k, "supi", sqn_bb, pk_bb, sk_bb, param)

def test_cred_issue_verify(bb_instance):
    bb = bb_instance
    (isk, ipk) = bb.IKeyGen(3)
    (G, o, g1, g2, e) = bb.params
    m = o.random()
    pm = o.random()
    (cred, pi_0) = bb.CredIssue(isk, ipk, m, pm)
    assert bb.CredVer(ipk, m, pm, cred, pi_0)

def test_key_exchange(bb_instance):
    bb = bb_instance
    (y, Y) = bb.AsymKeyGen()
    (a, A) = bb.KeyExchange_UE()
    (B, tau) = bb.KeyExchange_XN(A, Y, y)
    assert bb.KeyExchange_UE_Ver(Y, A, B, a, tau)

def test_cred_show_verify(bb_instance):
    bb = bb_instance
    (isk, ipk) = bb.IKeyGen(3)
    (tsk, tpk) = bb.LEAKeyGen()
    (y, Y) = bb.AsymKeyGen()
    (G, o, g1, g2, e) = bb.params
    m = o.random()
    pm = o.random()
    (cred, pi_0) = bb.CredIssue(isk, ipk, m, pm)
    (a, A) = bb.KeyExchange_UE()
    (B, tau) = bb.KeyExchange_XN(A, Y, y)
    keyEx = (A, B, tau)
    (Acred, pi_1, H) = bb.CredShow(ipk, tpk, m, pm, cred, keyEx)
    assert bb.AcredVer(ipk, tpk, m, Acred, pi_1, keyEx)

def test_trace_judge(bb_instance):
    bb = bb_instance
    (tsk, tpk) = bb.LEAKeyGen()
    (isk, ipk) = bb.IKeyGen(3)
    (y, Y) = bb.AsymKeyGen()
    (G, o, g1, g2, e) = bb.params
    m = o.random()
    pm = o.random()
    (cred, pi_0) = bb.CredIssue(isk, ipk, m, pm)
    (a, A) = bb.KeyExchange_UE()
    (B, tau) = bb.KeyExchange_XN(A, Y, y)
    keyEx = (A, B, tau)
    (Acred, pi_1, H) = bb.CredShow(ipk, tpk, m, pm, cred, keyEx)
    RL = []
    tm = bb.Trace(tsk, Acred)
    RL.append(tm)
    assert bb.judge(Acred, RL)
