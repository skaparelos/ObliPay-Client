import acl
import crypto
import wallet as modWallet
import database as dbUser
import requests
import time
import settings
from utils import debug_print

pparams = acl.pparams
url = settings.SERVER_URL

# profiling variables:
commServerTime = 0  # time spent in communication and at the server
proofTime = 0  # time spent making the proofs


def getSession():
    t0 = time.time()
    s = requests.Session()
    s.get(url + '/session/')
    t1 = time.time() - t0
    global commServerTime
    commServerTime += t1
    return s


def send(session, phase, encodedData):
    """Sends the message to the service and gets a result """
    t0 = time.time()
    s = session
    r = None

    try:
        r = s.post(url + '/acl/' + phase + '/', data={'data': str(encodedData)})
    except requests.exceptions.RequestException as e:
        print e
        exit(1)

    t1 = time.time() - t0
    global commServerTime
    commServerTime += t1

    return r.text


def showWallet():
    dbUser.printACs()


def seeTotalBalance():
    print dbUser.getTotalBalance()


def _getCoinData(coin):
    """ Gets coin data needed to complete the ACL protocol """
    denomination = coin.getDenomination()
    zeta1 = coin.getZeta1()
    # gamma, rnd, R
    secret_data = coin.getSecretData()
    return denomination, zeta1, secret_data


def _getToTheGamma(gamma):
    """ Returns h0^gamma, h1^gamma, and g^gamma """
    (_, _, g, _, _, hs) = pparams
    h0gamma = gamma * hs[0]
    h1gamma = gamma * hs[1]
    ggamma  = gamma * g
    return (h0gamma, h1gamma, ggamma)


def protocolSetup(protocol):
    """Chooses the coin(s) to use and initiates the appropriate protocol
    (spend, split, combine) with the right parameters"""

    if protocol == "spend":
        time_sent = time.time()

        (_, coin) = choose_coin()
        spendACL(coin)

    if protocol == "split":
        time_sent = time.time()

        # Get a coin to split
        (coin_id, coin) = choose_coin()
        denomination, _, _ = _getCoinData(coin)

        # ask for how much to take out and convert to int
        split1 = int(raw_input("How much to take out?:"))
        assert 0 <= split1 <= denomination
        split2 = denomination - split1

        # execute the splitACL protocol with the server
        coin1, coin2 = splitACL(coin, split1, split2)

        if coin1 == -1 or coin2 == -1:
            print "An error occurred. ACL protocol, couldn't complete"
            return -1

        # Invalidate the parent coin
        dbUser.invalidateACL(coin_id)

        # print time it took to mint coin
        time_diff = time.time() - time_sent
        debug_print("Time diff = " + str(time_diff))

        # Print success message to the user
        print "Created 2 coins:"
        print "1.Coin %s of value: %d" % (coin1.getAlias(), split1)
        print "2.Coin %s of value: %d" % (coin2.getAlias(), split2)

    if protocol == "combine":
        time_sent = time.time()

        # Choose 2 coins
        (coin1_id, coin1) = choose_coin()
        (coin2_id, coin2) = choose_coin()

        # Coins must not be the same
        assert coin1 != coin2
        assert coin1_id != coin2_id

        # execute the combine protocol with the server
        coin = combineACL(coin1, coin2)

        dbUser.invalidateACL(coin1_id)
        dbUser.invalidateACL(coin2_id)

        # print time it took to mint coin
        time_diff = time.time() - time_sent
        debug_print("Time diff = " + str(time_diff))

        print "Created a new coin:"
        print "Coin %s of value: %d" % (coin.getAlias(), coin.getDenomination())


def testSpend(coin, tries):
    for i in range(0, tries):
        spendACL(coin)
        coin = deposit(True)


def spendACL(coin):
    (_, o, _, _, _, hs) = pparams

    denomination, zeta1, secret_data = _getCoinData(coin)

    # calculate h0^gamma, h1^gamma, g^gamma
    (gamma, rnd, R) = secret_data
    toTheGamma = _getToTheGamma(gamma)
    (h0gamma, h1gamma, ggamma) = toTheGamma

    assert zeta1 == (R * h0gamma + denomination * h1gamma + rnd * ggamma)

    session = getSession()

    t0 = time.time()
    proof = crypto.proveSpend(pparams, gamma, R, denomination, rnd, toTheGamma, zeta1)
    assert crypto.verifySpend(pparams, (h0gamma, h1gamma, ggamma, zeta1), proof) == True

    toPack = [h0gamma, h1gamma, ggamma, zeta1, proof, coin.getACL()]
    encoded = crypto.marshall(toPack)
    # print "Spend size in bytes sent:", len(encoded)
    encoded_rcv = send(session, "spend", encoded)
    if encoded_rcv == "-1":
        print "couldn't spend coin"
        return -1


def testCombineACL(coin, tries):
    split1 = 0
    split2 = coin.getDenomination()

    for i in range(0, tries):
        coin1, coin2 = splitACL(coin, split1, split2)
        coin = combineACL(coin1, coin2)


def testSplitACL(coin, tries):
    """ run a deposit protocol to get a 'coin' and call this function
	    with the 'coin' as a parameter """
    split1 = 0
    split2 = coin.getDenomination()
    coin1, coin2 = splitACL(coin, split1, split2)

    for i in range(0, tries):
        _, coin2 = splitACL(coin2, split1, split2)


def splitACL(coin, split1, split2):
    """ The user chooses an ACL to split by some amount, and if everything
	goes well, gets 2 coins of splitted value. """
    (_, o, _, _, _, _) = pparams

    # Get coin denomination, zeta1, gamma, R, and rnd
    denomination, zeta1, secret_data = _getCoinData(coin)

    # calculate h0^gamma, h1^gamma, g^gamma
    (gamma, rnd, R) = secret_data
    (h0gamma, h1gamma, ggamma) = _getToTheGamma(gamma)

    assert zeta1 == (R * h0gamma + denomination * h1gamma + rnd * ggamma)

    t0 = time.time()
    proofs1 = crypto.proveCommitmentAndPositivity(pparams, split1)
    (Cp, Rp, proofCp, ComListp, proofListp) = proofs1
    proofp = (proofCp, ComListp, proofListp)

    proofs2 = crypto.proveCommitmentAndPositivity(pparams, split2)
    (Cpp, Rpp, proofCpp, ComListpp, proofListpp) = proofs2
    proofpp = (proofCpp, ComListpp, proofListpp)

    # Create proof that the two new commitment value adds up to the previous.
    # i.e. split1+split2 = denomination
    proof = crypto.proveSplitCoin(pparams, h0gamma, h1gamma, ggamma, R, gamma,
                                  Rp, split1, Rpp, split2, rnd, zeta1, Cp, Cpp)
    t1 = time.time() - t0
    global proofTime
    proofTime += t1

    ### ACL Registration ###
    # Prepate ACL Registration for coin1
    user_state_p = acl.StateHolder()
    user_state_p.C = Cp
    user_state_p.attributes = [split1]
    user_state_p.R = Rp
    # Prepare ACL Registration for coin2
    user_state_pp = acl.StateHolder()
    user_state_pp.C = Cpp
    user_state_pp.attributes = [split2]
    user_state_pp.R = Rpp

    ### ACL Preparation - ACL Validation 1 ###
    # pack
    toPack = [h0gamma, h1gamma, ggamma, zeta1, Cp, Cpp, proof, proofp, proofpp, coin.getACL()]
    encoded = crypto.marshall(toPack)
    debug_print("len splitACL registration = " +  str(len(encoded)))
    # get Session. Session lasts for a minute
    session = getSession()
    encoded_response = send(session, "split", encoded)
    debug_print("len prep-val1 (server to client) = " + str(len(encoded_response)))
    if encoded_response == "-1":
        print "splitACL didn't work"
        return -1
    
    # decode response
    # In this case a response is 3 things:
    # rnd, a, a1p, a2p for coin1
    # rnd, a, a1p, a2p for coin2
    # issuer_pub
    decoded_rcv = crypto.unmarshall(encoded_response)
    coin1_stuff = decoded_rcv[0]
    coin2_stuff = decoded_rcv[1]
    issuer_pub = decoded_rcv[2]

    ### ACL Validation 2 - Coin Creation ###
    (rnd_p, a_p, a1p_p, a2p_p) = coin1_stuff
    acl.BL_user_preparation(user_state_p, rnd_p)

    (rnd_pp, a_pp, a1p_pp, a2p_pp) = coin2_stuff
    acl.BL_user_preparation(user_state_pp, rnd_pp)

    ### ACL Validation 1 ###
    # make epsilon
    msg_to_issuer_p = acl.BL_user_validation(user_state_p, issuer_pub,
                                             (a_p, a1p_p, a2p_p))
    msg_to_issuer_pp = acl.BL_user_validation(user_state_pp, issuer_pub,
                                              (a_pp, a1p_pp, a2p_pp))

    ### ACL Validation 2 ###
    encoded = crypto.marshall([msg_to_issuer_p, msg_to_issuer_pp])  # pack
    debug_print("len prep - val1. (client to server) = " + str(len(encoded)))
    encoded_response = send(session, "validation2", encoded)
    debug_print("len validation2 =" + str(len(encoded_response)))
    # decode response
    (msg_from_issuer_p, msg_from_issuer_pp) = crypto.unmarshall(encoded_response)

    ### Signatures ###
    signature_p = acl.BL_user_validation2(user_state_p, msg_from_issuer_p)
    sig_p = acl.BL_user_prove_cred(user_state_p)

    signature_pp = acl.BL_user_validation2(user_state_pp, msg_from_issuer_pp)
    sig_pp = acl.BL_user_prove_cred(user_state_pp)

    ### Create Coin ###
    # TODO change to raw_input
    alias = "time coin"  # raw_input("Name/notes for this coin:")

    R_p = user_state_p.R
    gamma_p = user_state_p.gam
    rnd_p = user_state_p.rnd
    secret_data_p = (gamma_p, rnd_p, R_p)

    R_pp = user_state_pp.R
    gamma_pp = user_state_pp.gam
    rnd_pp = user_state_pp.rnd
    secret_data_pp = (gamma_pp, rnd_pp, R_pp)

    # Create coin and automatically save it
    coin1 = modWallet.ACL(split1, issuer_pub, signature_p, sig_p, secret_data_p,
                          alias, True)

    coin2 = modWallet.ACL(split2, issuer_pub, signature_pp, sig_pp , secret_data_pp, alias, True)

    return coin1, coin2


def deposit(testing = False):
    """ Mints an ACL """

    if testing == False:
        amount = raw_input("Enter the amount to make a coin:")
        amount = int(amount)
        timeSent = time.time()
    else:
        amount = 10

    # get session. Session lasts for a minute
    session = getSession()

    ### ACL registration ###

    # setup user locally
    user_state = acl.BL_user_setup([amount])
    user_commit = user_state.C

    # pack
    encoded = crypto.marshall([user_commit])

    # send
    debug_print("len deposit registration = " +  str(len(encoded)))
    encoded_rsp = send(session, "deposit", encoded)
    debug_print("len prep-val1 (server to client) = " + str(len(encoded_rsp)))
    if encoded_rsp == "-1":
        raise ValueError, "Something went wrong in the service."
    debug_print("deposit received = " + encoded_rsp)
    decoded_rsp = crypto.unmarshall(encoded_rsp)
    (rnd, a, a1p, a2p, issuer_pub) = decoded_rsp
    coin_stuff = (rnd, a, a1p, a2p)

    # if the code reaches here, then we can do the ACL protocol
    coin = ACL_protocol(amount, issuer_pub, user_state, session, coin_stuff)
    if coin == -1:
        raise ValueError, "Something went wrong while executing the ACL protocol"

    coin_, amount, alias = coin
    if settings.TESTING_MODE == False:
        timeDiff = time.time() - timeSent
        print "Time diff = ", timeDiff
        print "Successfully minted a coin"
        print "Coin %s of value: %d" % (alias, amount)

    return coin_


def ACL_protocol(amount, issuer_pub, user_state, session, coin_stuff):
    """ Runs the ACL protocol and creates a credential """
    (rnd, a, a1p, a2p) = coin_stuff

    ### ACL Preparation ###
    acl.BL_user_preparation(user_state, rnd)

    ### ACL Validation 1 ###
    # make epsilon
    msg_to_issuer = acl.BL_user_validation(user_state, issuer_pub, (a, a1p, a2p))

    ### ACL Validation 2 ###
    encoded = crypto.marshall([msg_to_issuer])
    debug_print("len prep-validation1 (client to server)= " +  str(len(encoded)))
    encoded_rcv = send(session, "validation2", encoded)
    debug_print("len validation2 (servet to client) = " + str(len(encoded_rcv)))
    debug_print("ACL_protocol response=" + encoded_rcv)
    (msg_from_issuer,) = crypto.unmarshall(encoded_rcv)

    ### Signatures ###
    signature = acl.BL_user_validation2(user_state, msg_from_issuer)

    sig = acl.BL_user_prove_cred(user_state)

    ### Create Coin ###
    # TODO change to raw_input
    alias = "time coin"  # raw_input("Name/notes for this coin:")

    R = user_state.R
    gamma = user_state.gam
    rnd = user_state.rnd
    secret_data = (gamma, rnd, R)

    # Create coin and automatically save it
    coin = modWallet.ACL(amount, issuer_pub, signature, sig, secret_data, alias, True)

    return coin, amount, alias


def combineACL(coin1, coin2):
    """ The user combines 2 ACLs to create a new one whose balance will be the
    sum of the 2. """

    timeSent = time.time()

    ## Get coin denomination, zeta1, gamma, R, and rnd for each coin
    # For coin 1:
    coin1Data = {}
    coin1Data["denomination"] = coin1.getDenomination()
    coin1Data["zeta1"] = coin1.getZeta1()
    (gamma, rnd, R) = coin1.getSecretData()
    coin1Data["gamma"] = gamma
    coin1Data["rnd"] = rnd
    coin1Data["R"] = R
    # For coin 2:
    coin2Data = {}
    coin2Data["denomination"] = coin2.getDenomination()
    coin2Data["zeta1"] = coin2.getZeta1()
    (gamma, rnd, R) = coin2.getSecretData()
    coin2Data["gamma"] = gamma
    coin2Data["rnd"] = rnd
    coin2Data["R"] = R

    ## Calculate h0^gamma, h1^gamma, g^gamma
    (_, o, g, _, _, hs) = pparams
    h0 = hs[0]
    h1 = hs[1]
    # for coin 1
    coin1Data["h0gamma"] = coin1Data["gamma"] * h0
    coin1Data["h1gamma"] = coin1Data["gamma"] * h1
    coin1Data["ggamma"] = coin1Data["gamma"] * g
    # for coin 2
    coin2Data["h0gamma"] = coin2Data["gamma"] * h0
    coin2Data["h1gamma"] = coin2Data["gamma"] * h1
    coin2Data["ggamma"] = coin2Data["gamma"] * g

    assert coin1Data["zeta1"] == (coin1Data["R"] * coin1Data["h0gamma"] +
                                  coin1Data["denomination"] * coin1Data[
                                      "h1gamma"] +
                                  coin1Data["rnd"] * coin1Data["ggamma"])

    assert coin2Data["zeta1"] == (coin2Data["R"] * coin2Data["h0gamma"] +
                                  coin2Data["denomination"] * coin2Data[
                                      "h1gamma"] +
                                  coin2Data["rnd"] * coin2Data["ggamma"])

    Rpp = o.random()
    C = Rpp * h0 + coin1Data["denomination"] * h1 + coin2Data[
                                                        "denomination"] * h1

    ## Set Public values
    nizkPublic = {}
    # coin 1 public
    nizkPublic["zeta1_c1"] = coin1Data["zeta1"]
    nizkPublic["h0gamma_c1"] = coin1Data["h0gamma"]
    nizkPublic["h1gamma_c1"] = coin1Data["h1gamma"]
    nizkPublic["ggamma_c1"] = coin1Data["ggamma"]
    # coin 2 public
    nizkPublic["zeta1_c2"] = coin2Data["zeta1"]
    nizkPublic["h0gamma_c2"] = coin2Data["h0gamma"]
    nizkPublic["h1gamma_c2"] = coin2Data["h1gamma"]
    nizkPublic["ggamma_c2"] = coin2Data["ggamma"]
    # add Commitment
    nizkPublic["C"] = C
    # nizkPublic["h0"] = h0
    # nizkPublic["h1"] = h1

    ## Set Secret values
    nizkSecret = {}
    # coin 1 secrets
    nizkSecret["R_c1"] = coin1Data["R"]
    nizkSecret["gamma_c1"] = coin1Data["gamma"]
    nizkSecret["x_c1"] = coin1Data["denomination"]
    nizkSecret["rnd_c1"] = coin1Data["rnd"]
    # coin 2 secrets
    nizkSecret["R_c2"] = coin2Data["R"]
    nizkSecret["gamma_c2"] = coin2Data["gamma"]
    nizkSecret["y_c2"] = coin2Data["denomination"]
    nizkSecret["rnd_c2"] = coin2Data["rnd"]
    # add commitment's R
    nizkSecret["Rpp"] = Rpp

    t0 = time.time()
    proof = crypto.proveCombineCoin(pparams, nizkPublic, nizkSecret)
    # assert crypto.verifyCombineCoin(nizkPublic, proof)
    t1 = time.time() - t0
    global proofTime
    proofTime += t1

    (issuer_pub, numAttr, signature, sig) = coin1.getACL()
    nizkPublic["issuer_pub_c1"] = issuer_pub
    nizkPublic["numAttr_c1"] = numAttr
    nizkPublic["signature_c1"] = signature
    nizkPublic["sig_c1"] = sig

    (issuer_pub, numAttr, signature, sig) = coin2.getACL()
    nizkPublic["issuer_pub_c2"] = issuer_pub
    nizkPublic["numAttr_c2"] = numAttr
    nizkPublic["signature_c2"] = signature
    nizkPublic["sig_c2"] = sig

    ### ACL Registration ###
    newDenomination = coin1Data["denomination"] + coin2Data["denomination"]
    user_state = acl.StateHolder()
    user_state.C = C
    user_state.attributes = [newDenomination]
    user_state.R = Rpp

    ### ACLCombine ###
    session = getSession()
    # send public stuff to the service
    encoded = crypto.marshall([nizkPublic, proof])
    debug_print("len combine registration = " + str(len(encoded)))
    encoded_rcv = send(session, "combine", encoded)
    debug_print("len prep-val1 (Server to client) = " + str(len(encoded_rcv)))
    if encoded_rcv == "-1":
        raise ValueError, "An error occurred. The service could not combine the two coins"

    # decode response
    debug_print("combine ACL response = " + encoded_rcv)
    decoded_rcv = crypto.unmarshall(encoded_rcv)
    (rnd, a, a1p, a2p, issuer_pub) = decoded_rcv
    coin_stuff = (rnd, a, a1p, a2p)

    coin = ACL_protocol(newDenomination, issuer_pub, user_state, session,
                        coin_stuff)
    coin_, _, _ = coin
    return coin_


def transferACL():
    """ Converts an ACL into a format that can be transferred and exports it in a file """

    # Get a coin to transfer
    (id, coin) = choose_coin()
    coin.save2transfer()
    # TODO: invalidate it?
    # dbUser.invalidateACL(id)
    return 0


def verifyACL():
    """ Spends a coin """

    # get a coin
    (coin_id, coin) = choose_coin()

    # Get details of the coin in the right format
    (issuer_pub, numAttr, signature, sig) = coin.getACL()
    # pack them
    toPack = [issuer_pub, numAttr, signature, sig]
    encoded = crypto.marshall(toPack)
    # send them
    encoded_rcv = send(None, "verify", encoded)
    # decode response
    m = crypto.unmarshall(encoded_rcv)

    if (m == False):
        print "Sorry, this coin is no longer valid!"
    else:
        print "Coin Spent!"

    # TODO: ask for coin deletion. The reason is that if something goes wrong
    # by auto deleting coins then the user might lose coins
    deleteCoin = raw_input("Delete coin " + str(coin_id) + " ?[y/n]")
    if deleteCoin == "y":
        dbUser.invalidateACL(coin_id)
    return 0


def getLastACL(numofIds):
    assert numofIds == 1 or numofIds == 2

    if numofIds == 1:
        coinChoice = dbUser.getLastACLid(1)
        return (coinChoice, modWallet.ACL.loadAC(coinChoice))

    if numofIds == 2:
        id1, id2 = dbUser.getLastACLid(2)
        coin1 = (id1, modWallet.ACL.loadAC(id1))
        coin2 = (id2, modWallet.ACL.loadAC(id2))
        return coin1, coin2

    return -1


def choose_coin():
    """ Choose a coin to use """

    # show all coins
    dbUser.printACs()

    # let the user choose one coin using the id
    coin_choice = raw_input("Set Main ACL:")
    try:
        coin_id = int(coin_choice)
    except ValueError:
        print 'Please enter an integer.'

    # load the coin id
    coin = modWallet.ACL.loadAC(coin_id)

    return (coin_id, coin)
