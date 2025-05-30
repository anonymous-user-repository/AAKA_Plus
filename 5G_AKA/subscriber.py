# subscriber.py
import socket
import sys
import pickle
import crypto
import datetime
from ecies import encrypt
import time

class Subscriber:
    def __init__(self, k, supi, sqn_ue, sname, port_sn, hn_pk):
        """
        Initialize the Subscriber class.

        Parameters:
            k (bytes): Key for cryptographic operations
            supi (str): Subscriber Permanent Identifier
            sqn_ue (int): Sequence number for User Equipment
            sname (str): Serving network name
            port_sn (int): Port number for Serving Network
            hn_pk (bytes): Public key for Home Network
        """
        self.k = k
        self.supi = supi
        self.sqn_ue = sqn_ue
        self.sname = sname
        self.port_sn = port_sn
        self.hn_pk = hn_pk

        # Connect to Serving Network
        try:
            self.sckt2sn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sckt2sn.connect(('127.0.0.1', port_sn))
            print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", " [Connected to Serving Network]")
        except socket.error as msg:
            print(msg)
            sys.exit(1)
    
    def connectSN(self):
        """
        Connect to the Serving Network and handle the authentication process.
        """
        # Initialize by sending SUCI
        suci = self.getSUCI()
        self.sckt2sn.send(pickle.dumps(suci))
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [Sent SUCI] suci: {suci}")

        # Receive R and AUTN
        r, autn = pickle.loads(self.sckt2sn.recv(1024 * 2))
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [Received R and AUTN] R: {r}, \nAUTN: {autn}")

        # Verify the received data
        i, ii, xsqn_hn = self.verify(self.k, r, autn)
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [Verification result] i: {i}, ii: {ii}")

        # Handle verification result
        if i and ii:
            self.sqn_ue = xsqn_hn
            res_star = self.getRES_star(self.k, r, self.sname)
            self.sckt2sn.send(pickle.dumps(('RES*', res_star)))
            print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [Sent RES*] RES*: {res_star}")
        elif i and not ii:
            auts = self.getAUTS(self.k, self.sqn_ue, r)
            self.sckt2sn.send(pickle.dumps(('Sync_Failure', auts)))
            print("\033[1;31m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [Sent 'Sync_Failure', AUTS] AUTS: {auts}")
        elif not i:
            self.sckt2sn.send(pickle.dumps(('Mac_Failure',)))
            print("\033[1;31m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [Sent 'Mac_Failure']")

        self.sckt2sn.close()

    def getSUCI(self):
        """
        Encrypt the SUPI to get the SUCI.

        Returns:
            bytes: Encrypted SUCI
        """
        start_time = time.time()
        for _ in range(1000):
            suci = self.supi
            suci_enc = encrypt(self.hn_pk, suci.encode('utf-8'))
        end_time = time.time()
        total_elapsed_time = end_time - start_time
        average_time_per_challenge = (total_elapsed_time / 1000) * 1000  # Convert to milliseconds
        formatted_time = f"{average_time_per_challenge:.2f} ms"
        print(f"UEgetSUCI execution time: {formatted_time}")
        return suci_enc

    def verify(self, k, r, autn):
        """
        Verify the AUTN value.

        Parameters:
            k (bytes): Key
            r (bytes): Random value
            autn (tuple): Authentication token (conc, mac)

        Returns:
            tuple: Verification result (bool, bool, int)
        """
        start_time = time.time()
        for _ in range(1000):
            xconc = autn[0]
            xmac = autn[1]
            ak = crypto.fun5(k, r)
            bxsqn_hn = crypto.getXOR(ak, xconc)
            xsqn_hn = int.from_bytes(bxsqn_hn, byteorder='little')
            mac = crypto.fun1(k, xsqn_hn, r)
            i = xmac == mac
            ii = self.sqn_ue < xsqn_hn
        end_time = time.time()
        total_elapsed_time = end_time - start_time
        average_time_per_challenge = (total_elapsed_time / 1000) * 1000  # Convert to milliseconds
        formatted_time = f"{average_time_per_challenge:.2f} ms"
        print(f"UEverify execution time: {formatted_time}")
        return i, ii, xsqn_hn

    def getRES_star(self, k, r, sname):
        """
        Generate the RES* value.

        Parameters:
            k (bytes): Key
            r (bytes): Random value
            sname (str): Serving network name

        Returns:
            bytes: RES* value
        """
        start_time = time.time()
        for _ in range(1000):
            cha = crypto.challenge(k, r, sname)
        end_time = time.time()
        total_elapsed_time = end_time - start_time
        average_time_per_challenge = (total_elapsed_time / 1000) * 1000  # Convert to milliseconds
        formatted_time = f"{average_time_per_challenge:.2f} ms"
        print(f"getRES_star execution time: {formatted_time}")
        return cha

    def getAUTS(self, k, sqn_ue, r):
        """
        Generate the AUTS value.

        Parameters:
            k (bytes): Key
            sqn_ue (int): Sequence number for User Equipment
            r (bytes): Random value

        Returns:
            tuple: AUTS value (conc_star, macs)
        """
        start_time = time.time()
        for _ in range(1000):
            macs = crypto.fun1_star(k, sqn_ue, r)
            ak_star = crypto.fun5_star(k, r)
            bsqn_ue = sqn_ue.to_bytes(256, byteorder='little')
            conc_star = crypto.getXOR(bsqn_ue, ak_star)
        end_time = time.time()
        elapsed_time = (end_time - start_time)
        formatted_time = f"{elapsed_time:.2f} ms"
        print(f"getAUTS execution time: {formatted_time}")
        return (conc_star, macs)

if __name__ == '__main__':
    k = crypto.getKey()
    sqn_ue = 99

    # Read public key of Home Network
    file_path = 'pkHN.dat'
    with open(file_path, 'rb') as file:
        pk_hn = file.read()

    scb = Subscriber(k, "supi", sqn_ue, "sname_100", 8080, pk_hn)
    scb.connectSN()
