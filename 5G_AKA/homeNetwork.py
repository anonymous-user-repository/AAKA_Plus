import socket
import sys
import pickle
import crypto
import datetime
from ecies.utils import generate_key
from ecies import decrypt
import time

class HomeNetwork:
    def __init__(self, k, supi, sqn_hn, port, pk_hn, sk_hn):
        """
        Initialize the HomeNetwork class.

        Parameters:
            k (bytes): Key for cryptographic operations
            supi (str): Subscriber Permanent Identifier
            sqn_hn (int): Sequence number for Home Network
            port (int): Port number for communication
            pk_hn (bytes): Public key for Home Network
            sk_hn (bytes): Secret key for Home Network
        """
        self.k = k
        self.supi = supi
        self.sqn_hn = sqn_hn
        self.port = port
        self.pk_hn = pk_hn
        self.sk_hn = sk_hn

        # Establish socket and wait for SN connection
        try:
            self.sckt_hn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sckt_hn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sckt_hn.bind(('127.0.0.1', port))
            self.sckt_hn.listen(10)
        except socket.error as msg:
            print(msg)
            sys.exit(1)
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", " [Waiting for SN connection...]")

    def connectSN(self):
        """
        Connect to SN (Serving Network) and perform authentication.
        """
        conn, addr = self.sckt_hn.accept()
        suci, sname = pickle.loads(conn.recv(1024 * 2))
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [Received suci, sname] suci: {suci}, sname: {sname}")

        # Get SUPI from SUCI
        supi = self.getSUPI(suci)

        # Start authentication challenge
        r, autn, hxres_star, k_seaf = self.authentication_challenge()
        conn.send(pickle.dumps((r, autn, hxres_star, k_seaf)))
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [Sent R, AUTN, HXRES*, K_SEAF] R: {r}, \nAUTN: {autn}, \nHXRES*: {hxres_star}, \nK_SEAF: {k_seaf}")

        # Receive response
        try:
            package = pickle.loads(conn.recv(1024 * 2))
        except EOFError:
            print("\033[1;31m", datetime.datetime.now().strftime("%F %T"), "\033[0m", " [Connection interrupted]")
            conn.close()
            return
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [Received from sub] package: (message, content), message: {package[0]}")

        # Handle response
        if package[0] == 'RES*':
            res_star = package[1]
            print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" ['RES*'] RES*: {res_star}")
            if res_star != self.xres_star:
                print("\033[1;31m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [RES* != HXRES*] Abort")
                sys.exit(1)
            else:
                conn.send(pickle.dumps(supi))
                print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [Sent SUPI to SN] supi: {supi}")

        elif package[0] == 'Sync_Failure':
            auts = package[1]
            r = package[2]
            print("\033[1;31m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" ['Sync_Failure'] AUTS: {auts}, \nR: {r}")
            i, xsqn_ue = self.verify(self.k, r, auts)
            if i:
                print("\033[1;31m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" ['MACS == MAC']")
                self.sqn_hn = xsqn_ue + 1
                print("\033[1;31m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [Resynchronized] sqn_hn: {self.sqn_hn}")
        conn.close()

    def getSUPI(self, suci):
        """
        Decrypt SUCI to get SUPI.

        Parameters:
            suci (str): Subscriber Concealed Identifier

        Returns:
            str: Subscriber Permanent Identifier
        """
        test_suci = suci
        start_time = time.time()
        for _ in range(1000):
            suci = decrypt(self.sk_hn, test_suci).decode('utf-8')
        end_time = time.time()
        total_elapsed_time = end_time - start_time
        average_time_per_challenge = (total_elapsed_time / 1000) * 1000  # Convert to milliseconds
        formatted_time = f"{average_time_per_challenge:.2f} ms"
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f"getSUPI execution time: {formatted_time}")

        if suci == "supi":
            return self.supi
        else:
            print("dec error!", suci)
            sys.exit(1)

    def authentication_challenge(self):
        """
        Perform the authentication challenge.

        Returns:
            tuple: Random value (r), Authentication token (autn), Hashed response (hxres_star), Session key (k_seaf)
        """
        start_time = time.time()
        for _ in range(1000):
            r = crypto.getRandom(256)
            bsqn_hn = self.sqn_hn.to_bytes(256, byteorder='little')
            self.mac = crypto.fun1(self.k, self.sqn_hn, r)
            ak = crypto.fun5(self.k, r)
            conc = crypto.getXOR(bsqn_hn, ak)
            autn = (conc, self.mac)
            self.xres_star = crypto.challenge(self.k, r, "sname_100")
            hxres_star = crypto.getsha256(r, self.xres_star)
            k_seaf = crypto.keySeed(self.k, r, self.sqn_hn, "sname_100")
        end_time = time.time()
        total_elapsed_time = end_time - start_time
        average_time_per_challenge = (total_elapsed_time / 1000) * 1000  # Convert to milliseconds
        formatted_time = f"{average_time_per_challenge:.2f} ms"
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f"authentication execution time: {formatted_time}")
        self.sqn_hn += 1
        return r, autn, hxres_star, k_seaf

    def verify(self, k, r, auts):
        """
        Verify the AUTS value.

        Parameters:
            k (bytes): Key
            r (bytes): Random value
            auts (tuple): AUTS value (conc_star, macs)

        Returns:
            tuple: Verification result (bool) and sequence number (int)
        """
        start_time = time.time()
        for _ in range(1000):
            conc_star = auts[0]
            macs = auts[1]
            xak_star = crypto.fun5(k, r)
            bxsqn_ue = crypto.getXOR(xak_star, conc_star)
            xsqn_ue = int.from_bytes(bxsqn_ue, byteorder='little')
            xmacs = crypto.fun1(k, xsqn_ue, r)
            if xmacs == macs:
                i = True
            else:
                i = False
        end_time = time.time()
        total_elapsed_time = end_time - start_time
        average_time_per_challenge = (total_elapsed_time / 1000) * 1000  # Convert to milliseconds
        formatted_time = f"{average_time_per_challenge:.2f} ms"
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f"ShowVerify execution time: {formatted_time}")
        return i, xsqn_ue

if __name__ == '__main__':
    k = crypto.getKey()
    # ECIES Key
    secp_k = generate_key()
    sk_hn = secp_k.secret  # bytes
    pk_hn = secp_k.public_key.format(True)  # bytes
    # Save public key to file
    file_path = 'pkHN.dat'

    with open(file_path, 'wb') as file:
        file.write(pk_hn)

    sqn_hn = 100
    hn = HomeNetwork(k, "supi", sqn_hn, 1070, pk_hn, sk_hn)
    hn.connectSN()
