""" Utils supporting coconut """
from bplib.bp import BpGroup
from petlib.bn import Bn
from hashlib import sha256

def setup(q=1):
	"""
	Generate the public parameters. 

	Parameters:
		- `q` (integer): the maximum number of attributes that can be embbed in the credentials

	Returns:
		- params: the publc parameters
	"""
	assert q > 0
	G = BpGroup()
	(g1, g2) = G.gen1(), G.gen2()
	# hs = [G.hashG1(("h%s" % i).encode("utf8")) for i in range(q)]
	(e, o) = G.pair, G.order()
	return (G, o, g1, g2, e)

class CocoException(Exception):
    pass

def coco_ensure(cond, message):
    if not cond:
        raise CocoException(message)

# ==================================================
# El-Gamal encryption scheme
# ==================================================
def elgamal_keygen(params):
   """ generate an El Gamal key pair """
   (G, o, g1, hs, g2, e) = params
   d = o.random()
   gamma = d * g1
   return (d, gamma)

def elgamal_enc(params, gamma, m, h):
    """ encrypts the values of a message (h^m) """
    (G, o, g1, hs, g2, e) = params
    k = o.random()
    a = k * g1
    b = k * gamma + m * h
    return (a, b, k)

def elgamal_dec(params, d, c):
    """ decrypts the message (h^m) """
    (G, o, g1, hs, g2, e) = params
    (a, b) = c
    return b - d*a


# ==================================================
# other
# ==================================================
def ec_sum(list):
	""" sum EC points list """
	ret = list[0]
	for i in range(1,len(list)):
		ret = ret + list[i]
	return ret


# ===================================================
# inversion
# ===================================================
def inv(a, n):  ### EDITED ###
	""" extended euclidean algorithm """
	if a == 0:
		return 0
	lm, hm = 1, 0
	low, high = a % n, n
	while low > 1:
		r = high//low
		nm, new = hm-lm*r, high-low*r
		lm, low, hm, high = nm, new, lm, low
	return lm % n

# ===================================================
# ZKP
# ===================================================
def challenge(elements):
        """Packages a challenge in a bijective way"""
        elem = [len(elements)] + elements
        elem_str = map(str, elem)
        elem_len = map(lambda x: "%s||%s" % (len(x), x), elem_str)
        state = "|".join(elem_len)
        H = sha256()
        H.update(state.encode("utf8"))
        return Bn.from_binary(H.digest())

