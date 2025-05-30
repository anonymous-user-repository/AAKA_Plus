import crypto
from ecies.utils import generate_key
from ecies import decrypt
# from bplib.bp import BpGroup, G2Elem
from utils import *


class AAKA_BB:
    def __init__(self, k, supi, sqn_bb, pk_bb, sk_bb, params):
        self.k = k
        self.supi = supi
        self.sqn_bb = sqn_bb
        self.pk_bb = pk_bb
        self.sk_bb = sk_bb
        self.params = params

    def IKeyGen(self, q):
        """
        Generate issuer key pair.

        Parameters:
            q (FieldElem): the maximum number of attributes

        Returns:
            isk (list): issuer secret key
            ipk (list): issuer public key
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
            tsk (FieldElem): LEA secret key
            tpk (G2Elem): LEA public key
        """
        (G, o, g1, g2, e) = self.params
        tsk = o.random()
        tpk = tsk * g2
        return (tsk, tpk)

    def AsymKeyGen(self):
        """
        Generate asymmetric key pair.

        Returns:
            sk (FieldElem): private key
            pk (G2Elem): public key
        """
        (G, o, g1, g2, e) = self.params
        sk = o.random()
        pk = sk * g1
        return (sk, pk)

    def CredIssue(self, isk, ipk, m, pm):
        """
        Issue a credential.

        Parameters:
            isk (list): issuer secret key
            ipk (list): issuer public key
            m (FieldElem): message
            pm (FieldElem): id

        Returns:
            cred (tuple): credential
            pi_0 (tuple): zero-knowledge proof
        """
        (G, o, g1, g2, e) = self.params
        sigma = inv((isk[0] + m * isk[1] + pm * isk[2]), o) * g1
        sigma_0 = isk[0] * sigma
        sigma_1 = isk[1] * sigma
        sigma_2 = isk[2] * sigma
        witness = isk
        stm = sigma
        pi_0 = self.ZK_prove_Relation_1(stm, witness)
        cred = (sigma, sigma_0, sigma_1, sigma_2)
        return (cred, pi_0)

    def ZK_prove_Relation_1(self, stm, witness):
        """
        Prove zero-knowledge relation 1.

        Parameters:
            stm (G2Elem): statement
            witness (list): witness

        Returns:
            commit (tuple): commitment
            list_s (list): responses
        """
        (G, o, g1, g2, e) = self.params
        rho_list, cmt, cmt_hat = [], [], []
        for i in range(len(witness)):
            rho = o.random()
            rho_list.append(rho)
            cmt.append(rho * stm)
            cmt_hat.append(rho * g2)
        ch = challenge(cmt + cmt_hat)
        list_s = []
        for i in range(len(witness)):
            list_s.append(rho_list[i] + witness[i] * ch)
        commit = (cmt, cmt_hat)
        return (commit, list_s)

    def ZK_Verify_Relation_1(self, ipk, cred, pi_0):
        """
        Verify zero-knowledge relation 1.

        Parameters:
            ipk (list): issuer public key
            cred (tuple): credential
            pi_0 (tuple): zero-knowledge proof

        Returns:
            bool: verification result
        """
        (G, o, g1, g2, e) = self.params
        (commit, list_s) = pi_0
        (cmt, cmt_hat) = commit
        ch = challenge(cmt + cmt_hat)
        for i in range(len(cred) - 1):
            if not (list_s[i] * cred[0] == cmt[i] + ch * cred[i + 1]) and (list_s[i] * g2 == cmt_hat[i] + ch * ipk[i]):
                return False
        return True

    def CredVer(self, ipk, m, pm, cred, pi_0):
        """
        Verify a credential.

        Parameters:
            ipk (list): issuer public key
            m (FieldElem): message
            pm (FieldElem): id
            cred (tuple): credential
            pi_0 (tuple): zero-knowledge proof

        Returns:
            bool: verification result
        """
        (G, o, g1, g2, e) = self.params
        (sigma, sigma_0, sigma_1, sigma_2) = cred
        (commit, list_s) = pi_0
        if (sigma_0 + m * sigma_1 + pm * sigma_2 == g1) and self.ZK_Verify_Relation_1(ipk, cred, pi_0):
            return True
        else:
            return False

    def KeyExchange_UE(self):
        """
        Perform user equipment key exchange.

        Returns:
            a (FieldElem): random value
            A (G2Elem): exchanged key
        """
        (G, o, g1, g2, e) = self.params
        a = o.random()
        A = a * g1
        return (a, A)

    def KeyExchange_XN(self, A, Y, y):
        """
        Perform XN key exchange.

        Parameters:
            A (G2Elem): key from user equipment
            Y (G2Elem): public key
            y (FieldElem): private key

        Returns:
            B (G2Elem): exchanged key
            tau (bytes): hashed key
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
            Y (G2Elem): public key
            A (G2Elem): key from user equipment
            B (G2Elem): exchanged key
            a (FieldElem): random value
            tau (bytes): hashed key

        Returns:
            bool: verification result
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
            ipk (list): issuer public key
            tpk (G2Elem): trustee public key
            m (FieldElem): message
            pm (FieldElem): id
            cred (tuple): credential
            keyEx (tuple): key exchange data

        Returns:
            Acred (tuple): anonymous credential
            pi_1 (tuple): zero-knowledge proof
            H (G2Elem): hashed key
        """
        (G, o, g1, g2, e) = self.params
        (sigma, sigma_0, sigma_1, sigma_2) = cred
        r, t, u = o.random(), o.random(), o.random()
        sigma_hat = r * sigma
        C1 = ipk[0] + m * ipk[1] + pm * ipk[2] + t * g2
        C2 = r * g1 + t * sigma_hat
        C3 = u * g2
        C4 = u * tpk + pm * g2
        H = challenge([sigma_hat, C1, C2, C3, C4, m]) * g1
        C5 = pm * H
        Acred = (sigma_hat, C1, C2, C3, C4, C5, m)
        witness = (pm, t, r, u)
        pi_1 = self.ZK_prove_Relation_2(Acred, witness, ipk, tpk, H, keyEx)
        return (Acred, pi_1, H)

    def ZK_prove_Relation_2(self, stm, witness, ipk, tpk, H, keyEx):
        """
        Prove zero-knowledge relation 2.

        Parameters:
            stm (tuple): statement
            witness (tuple): witness
            ipk (list): issuer public key
            tpk (G2Elem): trustee public key
            H (G2Elem): hashed key
            keyEx (tuple): key exchange data

        Returns:
            commit (tuple): commitment
            list_s (list): responses
        """
        (G, o, g1, g2, e) = self.params
        rho_list, cmt = [], []
        (sigma_hat, C1, C2, C3, C4, C5, m) = stm
        (A, B, tau) = keyEx
        (pm, t, r, u) = witness
        for i in range(len(witness)):
            rho = o.random()
            rho_list.append(rho)
        cmt_1 = rho_list[0] * ipk[2] + rho_list[1] * g2
        cmt_2 = rho_list[2] * g1 + rho_list[1] * sigma_hat
        cmt_3 = rho_list[3] * g2
        cmt_4 = rho_list[0] * g2 + rho_list[3] * tpk
        cmt_5 = rho_list[0] * H
        ch = challenge([cmt_1, cmt_2, cmt_3, cmt_4, cmt_5, A, B, tau])
        list_s = []
        for i in range(len(witness)):
            list_s.append(rho_list[i] + witness[i] * ch)
        commit = (cmt_1, cmt_2, cmt_3, cmt_4, cmt_5)
        return (commit, list_s)

    def ZK_Verify_Relation_2(self, ipk, tpk, Acred, pi_1, keyEx):
        """
        Verify zero-knowledge relation 2.

        Parameters:
            ipk (list): issuer public key
            tpk (G2Elem): trustee public key
            Acred (tuple): anonymous credential
            pi_1 (tuple): zero-knowledge proof
            keyEx (tuple): key exchange data

        Returns:
            bool: verification result
        """
        (G, o, g1, g2, e) = self.params
        (sigma_hat, C1, C2, C3, C4, C5, m) = Acred
        (commit, list_s) = pi_1
        (cmt_1, cmt_2, cmt_3, cmt_4, cmt_5) = commit
        (A, B, tau) = keyEx
        H = challenge([sigma_hat, C1, C2, C3, C4, m]) * g1
        ch = challenge([cmt_1, cmt_2, cmt_3, cmt_4, cmt_5, A, B, tau])
        eq_1 = list_s[0] * ipk[2] + list_s[1] * g2 == cmt_1 + ch * (C1 - (ipk[0] + m * ipk[1]))
        eq_2 = list_s[2] * g1 + list_s[1] * sigma_hat == cmt_2 + ch * C2
        eq_3 = list_s[3] * g2 == cmt_3 + ch * C3
        eq_4 = list_s[3] * tpk + list_s[0] * g2 == cmt_4 + ch * C4
        eq_5 = list_s[0] * H == cmt_5 + ch * C5
        if eq_1 and eq_2 and eq_3 and eq_4 and eq_5:
            return True
        else:
            return False

    def AcredVer(self, ipk, tpk, m, Acred, pi_1, keyEx):
        """
        Verify an anonymous credential.

        Parameters:
            ipk (list): issuer public key
            tpk (G2Elem): trustee public key
            m (FieldElem): message
            Acred (tuple): anonymous credential
            pi_1 (tuple): zero-knowledge proof
            keyEx (tuple): key exchange data

        Returns:
            bool: verification result
        """
        (G, o, g1, g2, e) = self.params
        (sigma_hat, C1, C2, C3, C4, C5, m) = Acred
        if e(sigma_hat, C1) == e(C2, g2) and self.ZK_Verify_Relation_2(ipk, tpk, Acred, pi_1, keyEx):
            return True
        else:
            return False

    def Trace(self, tsk, Acred):
        """
        Trace an anonymous credential.

        Parameters:
            tsk (FieldElem): trustee secret key
            Acred (tuple): anonymous credential

        Returns:
            tm (G2Elem): traced message
        """
        (G, o, g1, g2, e) = self.params
        (sigma_hat, C1, C2, C3, C4, C5, m) = Acred
        tm = C4 - tsk * C3
        return tm

    def judge(self, Acred, RL):
        """
        Judge if a user is revoked.

        Parameters:
            Acred (tuple): anonymous credential
            RL (list): revocation list

        Returns:
            bool: judge result
        """
        (G, o, g1, g2, e) = self.params
        (sigma_hat, C1, C2, C3, C4, C5, m) = Acred
        H = challenge([sigma_hat, C1, C2, C3, C4, m]) * g1
        for i in range(len(RL)):
            if e(H, RL[i]) == e(C5, g2):
                # collected in RL
                return True
        return False
