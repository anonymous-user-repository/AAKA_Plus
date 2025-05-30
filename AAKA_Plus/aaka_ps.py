import crypto
from ecies.utils import generate_key
from ecies import decrypt
from bplib.bp import BpGroup, G2Elem
from utils import *
import time

class AAKA_PS:
    def __init__(self, suci, params):
        """
        Initialize the AAKA_PS class.

        Parameters:
            suci (str): Subscriber Concealed Identifier
            params (tuple): Public parameters (G, o, g1, g2, e)
        """
        self.suci = suci
        self.params = params

    def IKeyGen(self, q):
        """
        Generate issuer key pair.

        Parameters:
            q (int): The maximum number of attributes

        Returns:
            tuple: Issuer secret key (isk) and issuer public key (ipk)
        """
        (G, o, g1, g2, e) = self.params
        list_x = [o.random() for _ in range(q)]
        isk = list_x
        ipk = ([xi * g2 for xi in list_x])
        return (isk, ipk)

    def LEAKeyGen(self):
        """
        Generate LEA key pair.

        Returns:
            tuple: LEA secret key (tsk) and LEA public key (tpk)
        """
        (G, o, g1, g2, e) = self.params
        tsk = o.random()
        tpk = tsk * g2
        return (tsk, tpk)

    def AsymKeyGen(self):
        """
        Generate asymmetric key pair.

        Returns:
            tuple: Private key (sk) and public key (pk)
        """
        (G, o, g1, g2, e) = self.params
        sk = o.random()
        pk = sk * g1
        return (sk, pk)

    def CredIssue(self, isk, ipk, m, pm):
        """
        Issue a credential.

        Parameters:
            isk (list): Issuer secret key
            ipk (list): Issuer public key
            m (bn): Message
            pm (bn): id

        Returns:
            tuple: Credential (cred) and zero-knowledge proof (pi_2)
        """
        (G, o, g1, g2, e) = self.params
        sigma_1 = o.random() * g1
        sigma_2 = (isk[0] + m * isk[1] + pm * isk[2]) * sigma_1
        witness = isk
        stm = sigma_1
        pi_2 = self.ZK_prove_Relation_3(stm, witness, m, pm)
        cred = (sigma_1, sigma_2)
        return (cred, pi_2)

    def ZK_prove_Relation_3(self, stm, witness, m, pm):
        """
        Prove zero-knowledge relation 3.

        Parameters:
            stm (G1Elem): Statement
            witness (list): Witness
            m (bn): Message
            pm (bn): id

        Returns:
            tuple: Commitment (commit) and responses (list_s)
        """
        (G, o, g1, g2, e) = self.params
        rho_list, cmt, cmt_hat = [], [], []
        for i in range(len(witness)):
            rho = o.random()
            rho_list.append(rho)
            cmt_hat.append(rho * g2)
        cmt.append((rho_list[0] + m * rho_list[1] + pm * rho_list[2]) * stm)
        ch = challenge(cmt + cmt_hat)
        list_s = []
        for i in range(len(witness)):
            list_s.append(rho_list[i] + witness[i] * ch)
        commit = (cmt, cmt_hat)
        return (commit, list_s)

    def ZK_Verify_Relation_3(self, ipk, cred, pi_2, m, pm):
        """
        Verify zero-knowledge relation 3.

        Parameters:
            ipk (list): Issuer public key
            cred (tuple): Credential
            pi_2 (tuple): Zero-knowledge proof
            m (bn): Message
            pm (bn): id

        Returns:
            bool: Verification result
        """
        (G, o, g1, g2, e) = self.params
        (commit, list_s) = pi_2
        (cmt, cmt_hat) = commit
        ch = challenge(cmt + cmt_hat)
        for i in range(len(cred) - 1):
            if not (list_s[i] * g2 == cmt_hat[i] + ch * ipk[i]):
                return False
        if not ((list_s[0] + m * list_s[1] + pm * list_s[2]) * cred[0] == cmt[0] + ch * cred[1]):
            return False
        return True

    def CredVer(self, ipk, m, pm, cred, pi_2):
        """
        Verify a credential.

        Parameters:
            ipk (list): Issuer public key
            m (Bn): Message
            pm (Bn): id
            cred (tuple): Credential
            pi_2 (tuple): Zero-knowledge proof

        Returns:
            bool: Verification result
        """
        (G, o, g1, g2, e) = self.params
        if self.ZK_Verify_Relation_3(ipk, cred, pi_2, m, pm):
            return True
        else:
            return False

    def KeyExchange_UE(self):
        """
        Perform user equipment key exchange.

        Returns:
            tuple: Random value (a) and exchanged key (A)
        """
        (G, o, g1, g2, e) = self.params
        a = o.random()
        A = a * g1
        return (a, A)

    def KeyExchange_XN(self, A, Y, y):
        """
        Perform XN key exchange.

        Parameters:
            A (G1Elem): Key from user equipment
            Y (G2Elem): Public key
            y (Bn): Private key

        Returns:
            tuple: Exchanged key (B) and hashed key (tau)
        """
        (G, o, g1, g2, e) = self.params
        b = o.random()
        B = b * g1
        delta = challenge([Y, A, B])
        K = (b + delta * y) * A
        tau = crypto.getsha256(K.export(), (0).to_bytes(1, byteorder='big'))
        self.k_s = crypto.getsha256(K.export(), (1).to_bytes(1, byteorder='big'))
        return (B, tau)

    def KeyExchange_UE_Ver(self, Y, A, B, a, tau):
        """
        Verify user equipment key exchange.

        Parameters:
            Y (G2Elem): Public key
            A (G1Elem): Key from user equipment
            B (G1Elem): Exchanged key
            a (Bn): Random value
            tau (bytes): Hashed key

        Returns:
            bool: Verification result
        """
        (G, o, g1, g2, e) = self.params
        delta = challenge([Y, A, B])
        K = a * (B + delta * Y)
        if tau == crypto.getsha256(K.export(), (0).to_bytes(1, byteorder='big')):
            self.k_s = crypto.getsha256(K.export(), (1).to_bytes(1, byteorder='big'))
            return True
        else:
            return False

    def CredShow(self, ipk, tpk, m, pm, cred, keyEx):
        """
        Show a credential.

        Parameters:
            ipk (list): Issuer public key
            tpk (G2Elem): Trustee public key
            m (Bn): Message
            pm (Bn): id
            cred (tuple): Credential
            keyEx (tuple): Key exchange data

        Returns:
            tuple: Anonymous credential (Acred), zero-knowledge proof (pi_3), and hashed key (H)
        """
        (G, o, g1, g2, e) = self.params
        (sigma_1, sigma_2) = cred
        r, t, u = o.random(), o.random(), o.random()
        sigma_1_hat = r * sigma_1
        sigma_2_hat = r * sigma_2 + t * sigma_1_hat
        C1 = ipk[0] + m * ipk[1] + pm * ipk[2] + t * g2
        C2 = u * g2
        C3 = u * tpk + pm * g2
        H = challenge([sigma_1_hat, sigma_2_hat, C1, C2, C3, m]) * g1
        C4 = pm * H
        Acred = (sigma_1_hat, sigma_2_hat, C1, C2, C3, C4, m)
        witness = (pm, t, u)
        pi_3 = self.ZK_prove_Relation_4(Acred, witness, ipk, tpk, H, keyEx)
        return (Acred, pi_3, H)

    def ZK_prove_Relation_4(self, stm, witness, ipk, tpk, H, keyEx):
        """
        Prove zero-knowledge relation 4.

        Parameters:
            stm (tuple): Statement
            witness (tuple): Witness
            ipk (list): Issuer public key
            tpk (G2Elem): Trustee public key
            H (G1Elem): Hashed key
            keyEx (tuple): Key exchange data

        Returns:
            tuple: Commitment (commit) and responses (list_s)
        """
        (G, o, g1, g2, e) = self.params
        rho_list, cmt = [], []
        (sigma_1_hat, sigma_2_hat, C1, C2, C3, C4, m) = stm
        (A, B, tau) = keyEx
        (pm, t, u) = witness
        for i in range(len(witness)):
            rho = o.random()
            rho_list.append(rho)
        cmt_1 = rho_list[0] * ipk[2] + rho_list[1] * g2
        cmt_2 = rho_list[2] * g2
        cmt_3 = rho_list[0] * g2 + rho_list[2] * tpk
        cmt_4 = rho_list[0] * H
        ch = challenge([cmt_1, cmt_2, cmt_3, cmt_4, A, B, tau])
        list_s = []
        for i in range(len(witness)):
            list_s.append(rho_list[i] + witness[i] * ch)
        commit = (cmt_1, cmt_2, cmt_3, cmt_4)
        return (commit, list_s)

    def ZK_Verify_Relation_4(self, ipk, tpk, Acred, pi_3, keyEx):
        """
        Verify zero-knowledge relation 4.

        Parameters:
            ipk (list): Issuer public key
            tpk (G2Elem): Trustee public key
            Acred (tuple): Anonymous credential
            pi_3 (tuple): Zero-knowledge proof
            keyEx (tuple): Key exchange data

        Returns:
            bool: Verification result
        """
        (G, o, g1, g2, e) = self.params
        (sigma_1_hat, sigma_2_hat, C1, C2, C3, C4, m) = Acred
        (commit, list_s) = pi_3
        (cmt_1, cmt_2, cmt_3, cmt_4) = commit
        (A, B, tau) = keyEx
        H = challenge([sigma_1_hat, sigma_2_hat, C1, C2, C3, m]) * g1
        ch = challenge([cmt_1, cmt_2, cmt_3, cmt_4, A, B, tau])
        eq_1 = list_s[0] * ipk[2] + list_s[1] * g2 == cmt_1 + ch * (C1 - (ipk[0] + m * ipk[1]))
        eq_2 = list_s[2] * g2 == cmt_2 + ch * C2
        eq_3 = list_s[2] * tpk + list_s[0] * g2 == cmt_3 + ch * C3
        eq_4 = list_s[0] * H == cmt_4 + ch * C4
        if eq_1 and eq_2 and eq_3 and eq_4:
            return True
        else:
            return False

    def AcredVer(self, ipk, tpk, m, Acred, pi_3, keyEx):
        """
        Verify an anonymous credential.

        Parameters:
            ipk (list): Issuer public key
            tpk (G2Elem): Trustee public key
            m (int): Message
            Acred (tuple): Anonymous credential
            pi_3 (tuple): Zero-knowledge proof
            keyEx (tuple): Key exchange data

        Returns:
            bool: Verification result
        """
        (G, o, g1, g2, e) = self.params
        (sigma_1_hat, sigma_2_hat, C1, C2, C3, C4, m) = Acred
        if e(sigma_1_hat, C1) == e(sigma_2_hat, g2) and self.ZK_Verify_Relation_4(ipk, tpk, Acred, pi_3, keyEx):
            return True
        else:
            return False

    def Trace(self, tsk, Acred):
        """
        Trace an anonymous credential.

        Parameters:
            tsk (int): Trustee secret key
            Acred (tuple): Anonymous credential

        Returns:
            G2Elem: Traced message
        """
        (G, o, g1, g2, e) = self.params
        (sigma_1_hat, sigma_2_hat, C1, C2, C3, C4, m) = Acred
        tm = C3 - tsk * C2
        return tm

    def judge(self, Acred, RL):
        """
        Judge if a user is revoked.

        Parameters:
            Acred (tuple): Anonymous credential
            RL (list): Revocation list

        Returns:
            bool: Judge result
        """
        (G, o, g1, g2, e) = self.params
        (sigma_1_hat, sigma_2_hat, C1, C2, C3, C4, m) = Acred
        H = challenge([sigma_1_hat, sigma_2_hat, C1, C2, C3, m]) * g1
        for i in range(len(RL)):
            if e(H, RL[i]) == e(C4, g2):
                return True
        return False

