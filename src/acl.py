# The Baldimtsi-Lysyanskaya Anonymous Credentials Light scheme
# See: 
#   Baldimtsi, Foteini, and Anna Lysyanskaya. "Anonymous credentials light." 
#   Proceedings of the 2013 ACM SIGSAC conference on Computer & communications security. 
#  ACM, 2013.

from hashlib import sha256
from base64 import b64encode

from petlib.bn import Bn
from petlib.ec import EcGroup, EcPt

from genzkp import *
import crypto

class StateHolder(object):
    pass

def BL_setup(Gid = 713):
    # Parameters of the BL schemes
    G = EcGroup(Gid)
    q = G.order()
    g = G.hash_to_point(b"g")
    h = G.hash_to_point(b"h")
    z = G.hash_to_point(b"z")
    hs = [G.hash_to_point(("h%s" % i).encode("utf8")) for i in range(2)] # 2-> hs[0], hs[1]
    return (G, q, g, h, z, hs)

pparams = BL_setup()


def BL_user_setup(attributes):
    (_, q, _, _, _, hs) = pparams
    L1 = attributes[0]

    R = q.random()
    C = R * hs[0] + L1 * hs[1] 

    #NIZK{(R, L1): C = h0^R * h1^L1 AND L1>=0 }
    #proofs = crypto.proveCommitmentAndPositivity(params, L1)
    #(C, R, proofC, ComList, proofList) = proofs
    #proofs = (proofC, ComList, proofList)
    #assert crypto._verifyCommitment(params, C, proofC)
    #assert crypto._verifyPositivity(params, (C, ComList, proofList))

    user_state = StateHolder()
    user_state.attributes = attributes
    user_state.C = C
    user_state.R = R

    return user_state


def BL_user_preparation(user_state, msg_from_issuer):
    (_, q, g, h, z, _) = pparams
    rnd = msg_from_issuer
    C = user_state.C

    z1 = C + rnd * g
    gam = q.random()
    zet = gam * z
    zet1 = gam * z1
    zet2 = zet + (-zet1)
    tau = q.random()
    eta = tau * z

    user_state.z1 = z1
    user_state.gam = gam
    user_state.zet = zet
    user_state.zet1 = zet1
    user_state.zet2 = zet2
    user_state.tau = tau
    user_state.eta = eta
    user_state.rnd = rnd


def BL_user_validation(user_state, issuer_pub, msg_to_user, message=b''):
    (G, q, g, h, _, _) = pparams
    # (z1, gam, zet, zet1, zet2, tau, eta) = user_private_state
    (a, a1p, a2p) = msg_to_user
    y  = issuer_pub

    assert G.check_point(a)
    assert G.check_point(a1p)
    assert G.check_point(a2p)

    t1,t2,t3,t4,t5 = [q.random() for _ in range(5)]
    alph = a + t1 * g + t2 * y
    alph1 = user_state.gam * a1p + t3 * g + t4 * user_state.zet1
    alph2 = user_state.gam * a2p + t5 * h + t4 * user_state.zet2

    # Make epsilon
    H = [user_state.zet, user_state.zet1, alph, alph1, alph2, user_state.eta]
    Hstr = list(map(EcPt.export, H)) + [message]
    Hhex = b"|".join(map(b64encode, Hstr))
    epsilon = Bn.from_binary(sha256(Hhex).digest()) % q
    
    e = epsilon.mod_sub(t2,q).mod_sub(t4, q)

    user_state.ts = [t1,t2,t3,t4,t5]
    user_state.message = message

    msg_to_issuer = e
    return msg_to_issuer


def BL_user_validation2(user_state, msg_from_issuer):
    (_, q, _, _, _, _) = pparams
    (c, r, cp, r1p, r2p) = msg_from_issuer
    (t1,t2,t3,t4,t5), m = user_state.ts, user_state.message

    gam = user_state.gam

    ro = r.mod_add(t1,q)
    om = c.mod_add(t2,q)
    ro1p = (gam * r1p + t3) % q
    ro2p = (gam * r2p + t5) % q
    omp = (cp + t4) % q
    mu = (user_state.tau - omp * gam) % q

    signature = (m, user_state.zet, 
                    user_state.zet1, 
                    user_state.zet2, om, omp, ro, ro1p, ro2p, mu)
    
    return signature


def BL_cred_proof(user_state):
    (_, q, g, _, z, hs) = pparams
    gam = user_state.gam

    assert user_state.zet == user_state.gam * z
    gam_hs = [gam * hsi for hsi in hs]
    gam_g = gam * g

    Cnew = user_state.rnd * gam_g + user_state.R * gam_hs[0]
    for i, attr in enumerate(user_state.attributes):
        Cnew = Cnew + attr * gam_hs[1+i]
    assert Cnew == user_state.zet1


def BL_show_zk_proof(params, num_attrib):
    (G, _, _, _, _, _) = params

    # Contruct the proof
    zk = ZKProof(G)

    ## The variables

    gam, rnd, R = zk.get(Sec, ["gam", "rnd", "R"])
    attrib = zk.get_array(Sec, "attrib", num_attrib, 0)

    g, z, zet, zet1 = zk.get(ConstGen, ["g", "z", "zet", "zet1"])
    hs = zk.get_array(ConstGen, "hs", num_attrib+1, 0)
    
    zk.add_proof(zet, gam * z)

    gam_g = zk.get(Gen, "gamg")
    zk.add_proof(gam_g, gam * g)

    gam_hs = zk.get_array(Gen, "gamhs", num_attrib+1, 0)

    for gam_hsi, hsi in zip(gam_hs, hs):
        zk.add_proof(gam_hsi, gam * hsi)
    
    Cnew = rnd * gam_g + R * gam_hs[0]
    for i, attr in enumerate(attrib):
        Cnew = Cnew + attr * gam_hs[1+i]

    zk.add_proof(zet1, Cnew)
    return zk


def BL_user_prove_cred(user_state):
    (_, _, g, _, z, hs) = pparams
    #zk = BL_show_zk_proof(user_state.params, len(user_state.attributes))
    zk = BL_show_zk_proof(pparams, len(user_state.attributes))

    env = ZKEnv(zk)

    # The secrets
    env.gam = user_state.gam
    env.rnd = user_state.rnd
    env.R   = user_state.R
    env.attrib = user_state.attributes

    # Constants
    env.g = g
    env.z = z
    env.zet = user_state.zet
    env.zet1 = user_state.zet1
    env.hs = hs[:len(user_state.attributes) + 1]

    # The stored generators
    env.gamg = user_state.gam * g
    env.gamhs = [user_state.gam * hsi for hsi in hs[:len(user_state.attributes) + 1]]

    ## Extract the proof
    sig = zk.build_proof(env.get())
    if __debug__:
        assert zk.verify_proof(env.get(), sig, strict=False)

    return sig

