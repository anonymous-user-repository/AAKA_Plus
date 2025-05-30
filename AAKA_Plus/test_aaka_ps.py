import pytest
from aaka_ps import AAKA_PS
from utils import setup
import crypto
from ecies.utils import generate_key
from bplib.bp import G2Elem

@pytest.fixture
def ps_instance():
    params = setup(3)
    suci = "supi"
    return AAKA_PS(suci, params)

def test_cred_issue_verify(ps_instance):
    ps = ps_instance
    (isk, ipk) = ps.IKeyGen(3)
    (G, o, g1, g2, e) = ps.params
    m = o.random()
    pm = o.random()
    (cred, pi_2) = ps.CredIssue(isk, ipk, m, pm)
    assert ps.CredVer(ipk, m, pm, cred, pi_2)

def test_key_exchange(ps_instance):
    ps = ps_instance
    (y, Y) = ps.AsymKeyGen()
    (a, A) = ps.KeyExchange_UE()
    (B, tau) = ps.KeyExchange_XN(A, Y, y)
    assert ps.KeyExchange_UE_Ver(Y, A, B, a, tau)

def test_cred_show_verify(ps_instance):
    ps = ps_instance
    (isk, ipk) = ps.IKeyGen(3)
    (tsk, tpk) = ps.LEAKeyGen()
    (y, Y) = ps.AsymKeyGen()
    (G, o, g1, g2, e) = ps.params
    m = o.random()
    pm = o.random()
    (cred, pi_2) = ps.CredIssue(isk, ipk, m, pm)
    (a, A) = ps.KeyExchange_UE()
    (B, tau) = ps.KeyExchange_XN(A, Y, y)
    keyEx = (A, B, tau)
    (Acred, pi_3, H) = ps.CredShow(ipk, tpk, m, pm, cred, keyEx)
    assert ps.AcredVer(ipk, tpk, m, Acred, pi_3, keyEx)

def test_trace_judge(ps_instance):
    ps = ps_instance
    (tsk, tpk) = ps.LEAKeyGen()
    (isk, ipk) = ps.IKeyGen(3)
    (y, Y) = ps.AsymKeyGen()
    (G, o, g1, g2, e) = ps.params
    m = o.random()
    pm = o.random()
    (cred, pi_2) = ps.CredIssue(isk, ipk, m, pm)
    (a, A) = ps.KeyExchange_UE()
    (B, tau) = ps.KeyExchange_XN(A, Y, y)
    keyEx = (A, B, tau)
    (Acred, pi_3, H) = ps.CredShow(ipk, tpk, m, pm, cred, keyEx)
    RL = []
    tm = ps.Trace(tsk, Acred)
    RL.append(tm)
    assert ps.judge(Acred, RL)
