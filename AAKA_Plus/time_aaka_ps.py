import time
from aaka_ps import AAKA_PS
from utils import setup
import crypto
from ecies.utils import generate_key

def performance_test():
    """
    Run performance tests for various functions in AAKA_PS.
    """
    suci = "suci"
    params = setup(3)
    ps = AAKA_PS(suci, params)

    (isk, ipk) = ps.IKeyGen(3)
    (tsk, tpk) = ps.LEAKeyGen()
    (y, Y) = ps.AsymKeyGen()
    (G, o, g1, g2, e) = params
    m = o.random()
    pm = o.random()

    def measure_time(func, *args):
        """
        Measure the execution time of a function over 1000 iterations.

        Parameters:
            func (function): The function to measure
            args: The arguments to pass to the function
        """
        start_time = time.time()
        for _ in range(1000):
            func(*args)
        end_time = time.time()
        # Convert to milliseconds(1000 iterations)
        elapsed_time = ((end_time - start_time)/1000)* 1000
        formatted_time = f"{elapsed_time:.2f} ms"
        print(f"{func.__name__} execution time: {formatted_time}")

    measure_time(setup, 3)
    measure_time(ps.CredIssue, isk, ipk, m, pm)
    measure_time(ps.CredVer, ipk, m, pm, ps.CredIssue(isk, ipk, m, pm)[0], ps.CredIssue(isk, ipk, m, pm)[1])
    measure_time(ps.KeyExchange_UE)
    measure_time(ps.KeyExchange_XN, ps.KeyExchange_UE()[1], Y, y)
    (B, tau) = ps.KeyExchange_XN(ps.KeyExchange_UE()[1], Y, y)
    measure_time(ps.KeyExchange_UE_Ver, Y, ps.KeyExchange_UE()[1], B, ps.KeyExchange_UE()[0], tau)
    measure_time(ps.CredShow, ipk, tpk, m, pm, ps.CredIssue(isk, ipk, m, pm)[0], (ps.KeyExchange_UE()[1], B, tau))
    (Acred, pi_3, H) = ps.CredShow(ipk, tpk, m, pm, ps.CredIssue(isk, ipk, m, pm)[0], (ps.KeyExchange_UE()[1], B, tau))
    measure_time(ps.AcredVer, ipk, tpk, m, Acred, pi_3, (ps.KeyExchange_UE()[1], B, tau))
    measure_time(ps.Trace, tsk, Acred)
    measure_time(ps.judge, Acred, [ps.Trace(tsk, Acred)])

if __name__ == '__main__':
    performance_test()
