# servingNetwork.py
import socket
import sys
import pickle
import crypto
import datetime

class ServingNetwork:
    def __init__(self, sname, suci, port):
        """
        Initialize the ServingNetwork class.

        Parameters:
            sname (str): Serving network name
            suci (str): Subscriber Concealed Identifier
            port (int): Port number for communication
        """
        self.sname = sname
        self.suci = suci
        self.port = port

        # Establish socket and wait for sub (subscriber) connection
        try:
            self.sckt_sn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sckt_sn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sckt_sn.bind(('127.0.0.1', port))
            self.sckt_sn.listen(10)
        except socket.error as msg:
            print(msg)
            sys.exit(1)
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", " [Waiting for subscriber to connect...]")
        
    def connectHN(self, port_hn):
        """
        Connect to the Home Network (HN).

        Parameters:
            port_hn (int): Port number for Home Network
        """
        try:
            self.sckt2hn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sckt2hn.connect(('127.0.0.1', port_hn))
        except socket.error as msg:
            print(msg)
            sys.exit(1)

    def transfer(self):
        """
        Handle communication between the subscriber and the Home Network.
        """
        # Receive SUCI from subscriber
        conn, addr = self.sckt_sn.accept()
        suci = pickle.loads(conn.recv(1024 * 2))
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [Received SUCI from subscriber] suci: {suci}")

        # Send SUCI and sname to Home Network
        self.connectHN(1070)
        self.sckt2hn.send(pickle.dumps((suci, self.sname)))
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [Sent SUCI and sname to HN] suci: {suci}, sname: {self.sname}")

        # Receive R, AUTN, HXRES*, K_SEAF from Home Network
        r, autn, hxres_star, k_seaf = pickle.loads(self.sckt2hn.recv(1024))
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [Received R, AUTN, HXRES*, K_SEAF from HN] R: {r}, \nAUTN: {autn}, \nHXRES*: {hxres_star}, \nK_SEAF: {k_seaf}")

        # Send R and AUTN to subscriber
        conn.send(pickle.dumps((r, autn)))
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [Sent R and AUTN to subscriber] R: {r}, AUTN: {autn}")

        # Receive response from subscriber
        package = pickle.loads(conn.recv(1024 * 2))
        print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [Received response from subscriber] package: {package}")

        # Handle different types of responses
        if package[0] == 'Mac_Failure':
            print("\033[1;31m", datetime.datetime.now().strftime("%F %T"), "\033[0m", " [Mac_Failure] Abort")
        
        elif package[0] == 'Sync_Failure':
            auts = package[1]
            self.sckt2hn.send(pickle.dumps(('Sync_Failure', auts, r, suci)))
            print("\033[1;31m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [Sent 'Sync_Failure', AUTS, R, SUCI to HN] AUTS: {auts}, \nR: {r}, \nsuci: {suci}")

        elif package[0] == 'RES*':
            res_star = package[1]
            print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [Received RES*] RES*: {res_star}")
            if crypto.getsha256(r, res_star) != hxres_star:
                print("\033[1;31m", datetime.datetime.now().strftime("%F %T"), "\033[0m", " [SHA256(<R, RES*>) != HXRES*] Abort")
                sys.exit(1)
            else:
                self.sckt2hn.send(pickle.dumps(('RES*', res_star, suci)))
                print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [Sent RES* and suci to HN] RES*: {res_star}, suci: {suci}")
                supi = pickle.loads(self.sckt2hn.recv(1024 * 2))
                print("\033[1;32m", datetime.datetime.now().strftime("%F %T"), "\033[0m", f" [Received SUPI from HN] supi: {supi}")

        conn.close()
        self.sckt2hn.close()

if __name__ == '__main__':
    sn = ServingNetwork("sname_100", "suci", 8080)
    sn.transfer()
