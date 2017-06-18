import petlib
from petlib.bn import Bn
from petlib.ec import EcGroup, Bn, EcPt
from binascii import hexlify, unhexlify
from hashlib import sha256
import msgpack # pip install msgpack-python
import utils
import base64


def marshall(to_pack):
    packed = msgpack.packb(to_pack, default=utils.default, use_bin_type=True)
    packed_encoded = base64.b64encode(packed)
    return packed_encoded


def unmarshall(packed_encoded):
    packed = base64.b64decode(packed_encoded)
    data = msgpack.unpackb(packed, ext_hook=utils.ext_hook, encoding='utf-8')
    return data


# function taken from
# https://github.com/gdanezis/petlib/blob/master/examples/GK15ringsig.py
def _challenge(elements):
    """Packages a challenge in a bijective way"""
    elem = [len(elements)] + elements
    elem_str = list(map(str, elem))
    elem_len = list(map(lambda x: "%s||%s" % (len(x), x), elem_str))
    state = "|".join(elem_len)
    H = sha256()
    H.update(state.encode("utf8"))
    return Bn.from_binary(H.digest())


def proveSpend(params, gamma, R, L1, rnd, toTheGamma, zeta1):
    (_, o, g, _, z, hs) = params
    (h0gamma, h1gamma, ggamma) = toTheGamma

    w_gamma = o.random()
    w_R = o.random()
    w_L1 = o.random()
    w_rnd = o.random()

    # TODO loipoun ta h0^gamma..
    # TODO loipoun polla
    W1 = w_R * h0gamma + w_L1 * h1gamma + w_rnd * ggamma

    c = _challenge([hs[0], hs[1], g, z, h0gamma, h1gamma, ggamma, zeta1, W1])

    r_R = (w_R - c * R) % o
    r_gamma = (w_gamma - c * gamma) % o
    r_L1 = (w_L1 - c * L1) % o
    r_rnd = (w_rnd - c * rnd) % o
    responses = (r_R, r_gamma, r_L1, r_rnd)

    return (c, responses)


def verifySpend(params, publicParams, proof):
    (h0gamma, h1gamma, ggamma, zeta1) = publicParams
    (_, o, g, _, z, hs) = params

    (c, responses) = proof
    (r_R, r_gamma, r_L1, r_rnd) = responses

    W1 = r_R * h0gamma + r_L1 * h1gamma + r_rnd * ggamma + c * zeta1

    return _challenge(
        [hs[0], hs[1], g, z, h0gamma, h1gamma, ggamma, zeta1, W1]) == c


def _get32bitRepr(number):
    """ Returns the 32-bit Binary Representation of a number. """
    return '{0:032b}'.format(number)


def _prove_range(params, num):
    """ Creates a commitment com = h0^num h1^r
        and proves that 'num' lies in the range [0,2^32]
        Returns the commitment 'com', the randomness 'r',
        the proof of the opennings of the commitment 'proofCom',
        the 32 bit commitments 'commitmentsList',
        and the proof that they open to {0,1} 'proofList'.
    """

    if int(num) < 0:
        print  "Please Enter a positive number."
        return -1

    (_, o, _, _, _, hs) = params
    num_binary = _get32bitRepr(num)

    commitmentsList = []
    proofList = []
    r = 0

    # x = x0*2^0 + x1*2^1 + ... + xl-1*2^(l-1)
    # r = r0*2^0 + r1*2^1 + ... + rl-1*2^(l-1)
    # Need to reverse the number
    for i, c in enumerate(num_binary[::-1]):
        # get a random number for each bit
        ri = o.random()
        # calculate r = Sum(ri * 2^i)%o
        r += (ri * (2 ** i))

        # make the commitment and add it to the list
        com = Com(hs[0], ri, hs[1], int(c))
        commitmentsList.append(com)

        # Prove that the committed value is a bit
        proof = _ProveZeroOne(params, com, int(c), ri)
        proofList.append(proof)

    r = r % o
    # Now commit to E(x,r) where r = Sum(ri)
    com = Com(hs[0], r, hs[1], num)
    proofCom = _proveCommitment(params, com, num, r)
    return (com, r, proofCom, commitmentsList, proofList)


def Com(h0, r, h1, m):
    """ Pedersen Commitment """
    return r * h0 + m * h1


def doubleCom(h0, r1, r2, h1, m1, m2):
    return r1 * h0 + m1 * h1, r2 * h0 + m2 * h1


# function taken from
# https://github.com/gdanezis/petlib/blob/master/examples/GK15ringsig.py
def _ProveZeroOne(params, c, m, r):
    """
    Simple proof that a Commitment c = Com(m,r) is either 0 or 1
    To read more about the proof see the paper "How to leak a secret and
    spend a coin" page 8 by Groth & Kohlweiss
    """
    (_, o, _, _, _, hs) = params
    # assert Com(hs[0], r, hs[1], m) == c
    a, s, t = o.random(), o.random(), o.random()
    # ca = Com(hs[0], s, hs[1], a)
    # cb = Com(hs[0], t, hs[1], a*m)
    ca, cb = doubleCom(hs[0], s, t, hs[1], a, a * m)
    x = _challenge([hs[0], hs[1], ca, cb]) % o
    f = (x * m + a) % o
    za = (r * x + s) % o
    zb = (r * (x - f) + t) % o
    return (x, f, za, zb)


def _proveCommitment(params, C, m, r):
    """ Prove knowledge of the secrets within a commitment, 
        as well as the opening of the commitment.
    """
    (_, o, _, _, _, hs) = params

    # NIZK{(r,m): C= h0^m * h1^r }
    w0 = o.random()
    w1 = o.random()
    W = w0 * hs[0] + w1 * hs[1]
    c = _challenge([hs[0], hs[1], C, W])
    r0 = (w0 - c * r) % o
    r1 = (w1 - c * m) % o
    return (c, (r0, r1))


def proveSplitCoin(params, h0gamma, h1gamma, ggamma, R, gamma, Rp, split1, Rpp,
                   split2, rnd, zeta1, Cp, Cpp):
    (_, o, g, _, _, hs) = params
    h0 = hs[0]
    h1 = hs[1]

    w_R = o.random()
    w_gamma = o.random()
    w_Rp = o.random()
    w_split1 = o.random()
    w_Rpp = o.random()
    w_split2 = o.random()
    w_rnd = o.random()

    # TODO loipoun ta h0^gamma proofs...

    W1 = w_R * h0gamma + w_split1 * h1gamma + w_split2 * h1gamma + w_rnd * ggamma
    W2 = w_Rp * h0 + w_split1 * h1
    W3 = w_Rpp * h0 + w_split2 * h1

    c = _challenge([h0, h1, g, h0gamma, h1gamma, ggamma, zeta1, Cp, Cpp, W1, W2,
                    W3])

    r_R       = (w_R - c * R) % o
    r_gamma   = (w_gamma - c * gamma) % o
    r_Rp      = (w_Rp - c * Rp) % o
    r_split1  = (w_split1 - c * split1) % o
    r_Rpp     = (w_Rpp - c * Rpp) % o
    r_split2  = (w_split2 - c * split2) % o
    r_rnd     = (w_rnd - c * rnd) % o
    responses = (r_R, r_gamma, r_Rp, r_split1, r_Rpp, r_split2, r_rnd)

    return (c, responses)


def proveCombineCoin(params, public, secret):
    (_, o, g, _, _, hs) = params

    w_R = o.random()
    w_gamma = o.random()
    w_x = o.random()
    w_rnd = o.random()
    w_Rp = o.random()
    w_gammap = o.random()
    w_y = o.random()
    w_rndp = o.random()
    w_Rpp = o.random()

    W1 = w_R * public["h0gamma_c1"] + w_x * public["h1gamma_c1"] + \
         w_rnd * public["ggamma_c1"]

    W2 = w_Rp * public["h0gamma_c2"] + w_y * public["h1gamma_c2"] + \
         w_rndp * public["ggamma_c2"]

    W3 = w_Rpp * hs[0] + w_x * hs[1] + w_y * hs[1]

    c = _challenge([hs[0],hs[1], public["h0gamma_c1"], public["h1gamma_c1"],
                    public["ggamma_c1"], public["h0gamma_c2"],
                    public["h1gamma_c2"], public["ggamma_c2"],
                    public["zeta1_c1"], public["zeta1_c2"], public["C"],
                    W1, W2, W3])

    # Responses
    r_R = (w_R - c * secret["R_c1"]) % o
    r_gamma = (w_gamma - c * secret["gamma_c1"]) % o
    r_x = (w_x - c * secret["x_c1"]) % o
    r_rnd = (w_rnd - c * secret["rnd_c1"]) % o
    r_Rp = (w_Rp - c * secret["R_c2"]) % o
    r_gammap = (w_gammap - c * secret["gamma_c2"]) % o
    r_y = (w_y - c * secret["y_c2"]) % o
    r_rndp = (w_rndp - c * secret["rnd_c2"]) % o
    r_Rpp = (w_Rpp - c * secret["Rpp"]) % o

    responses = (r_R, r_gamma, r_x, r_rnd, r_Rp, r_gammap, r_y, r_rndp, r_Rpp)

    return (c, responses)


def proveCommitmentAndPositivity(params, x):
    return _prove_range(params, x)


def _verifyCommitment(params, C, proof):
    """ Verify a proof of knowledge of the commitment.
        Return a boolean denoting whether the verification succeeded. """
    (_, _, _, _, _, hs) = params
    c, (r0, r1) = proof
    W = r0 * hs[0] + r1 * hs[1] + c * C
    return _challenge([hs[0], hs[1], C, W]) == c


def _verifyPositivity(params, listP):
    ''' Verifies that a 32 bit number is positive or 0. '''
    # TODO : assert len(listP) == 32

    (com, commitmentsList, proof_list) = listP

    Product_Com = commitmentsList[0]
    assert _VerifyZeroOne(params, commitmentsList[0], proof_list[0]) == True

    for i, c in enumerate(commitmentsList[1:]):
        # Verify that it is 0 or 1
        assert _VerifyZeroOne(params, c, proof_list[i + 1]) == True
        # Product(Com(xi,ri)^2i)
        Product_Com = Product_Com + (2 ** (i + 1)) * c

    # E(x,r)  == Product( E(xi,ri) )
    return com == Product_Com


def _VerifyZeroOne(params, c, proof):
    """ Verify that a Commitment c = Com(m,r) is either 0 or 1 """
    (_, o, _, _, _, hs) = params
    (x, f, za, zb) = proof

    assert 0 < x < o
    assert 0 < f < o
    assert 0 < za < o
    assert 0 < zb < o

    ca = Com(hs[0], za, hs[1], f) - x * c
    cb = Com(hs[0], zb, hs[1], 0) - (x - f) * c
    xp = _challenge([hs[0], hs[1], ca, cb]) % o
    return xp == x
