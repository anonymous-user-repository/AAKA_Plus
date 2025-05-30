import time
from aaka_bb import AAKA_BB
from utils import setup
import crypto
from ecies.utils import generate_key

def performance_test():
    k = crypto.getKey()
    secp_k = generate_key()
    sk_bb = secp_k.secret
    pk_bb = secp_k.public_key.format(True)
    sqn_bb = 100
    param = setup(3)
    bb = AAKA_BB(k, "supi", sqn_bb, pk_bb, sk_bb, param)

    (isk, ipk) = bb.IKeyGen(3)
    (tsk, tpk) = bb.LEAKeyGen()
    (y, Y) = bb.AsymKeyGen()
    (G, o, g1, g2, e) = param
    m = o.random()
    pm = o.random()

    def measure_time(func, *args):
        start_time = time.time()
        for _ in range(1000):
            func(*args)
        end_time = time.time()
        # Convert to milliseconds(1000 iterations)
        elapsed_time = ((end_time - start_time)/1000)* 1000
        formatted_time = f"{elapsed_time:.2f} ms"
        print(f"{func.__name__} execution time: {formatted_time}")

    measure_time(setup, 3)
    measure_time(bb.CredIssue, isk, ipk, m, pm)
    measure_time(bb.CredVer, ipk, m, pm, bb.CredIssue(isk, ipk, m, pm)[0], bb.CredIssue(isk, ipk, m, pm)[1])
    measure_time(bb.KeyExchange_UE)
    measure_time(bb.KeyExchange_XN, bb.KeyExchange_UE()[1], Y, y)
    (B, tau) = bb.KeyExchange_XN(bb.KeyExchange_UE()[1], Y, y)
    measure_time(bb.KeyExchange_UE_Ver, Y, bb.KeyExchange_UE()[1], B, bb.KeyExchange_UE()[0], tau)
    measure_time(bb.CredShow, ipk, tpk, m, pm, bb.CredIssue(isk, ipk, m, pm)[0], (bb.KeyExchange_UE()[1],bb.KeyExchange_XN(bb.KeyExchange_UE()[1], Y, y)[0],bb.KeyExchange_XN(bb.KeyExchange_UE()[1], Y, y)[1]))
    (Acred, pi_1, H) = bb.CredShow(ipk, tpk, m, pm, bb.CredIssue(isk, ipk, m, pm)[0], (bb.KeyExchange_UE()[1],bb.KeyExchange_XN(bb.KeyExchange_UE()[1], Y, y)[0],bb.KeyExchange_XN(bb.KeyExchange_UE()[1], Y, y)[1]))
    measure_time(bb.AcredVer, ipk, tpk, m, Acred, pi_1,(bb.KeyExchange_UE()[1], B, tau))
    measure_time(bb.Trace, tsk, Acred)
    measure_time(bb.judge, Acred, [bb.Trace(tsk, Acred)])

if __name__ == '__main__':
    performance_test()
