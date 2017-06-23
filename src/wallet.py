import database as dbUser
import crypto


class ACL(object):
    def __init__(self, denomination, issuer_pub, signature, sig, secret_data,
                 alias='', boolSave=True):
        self.denomination = denomination
        self.issuer_pub = issuer_pub
        self.signature = signature
        self.sig = sig
        self.numAttributes = 1  # always set to 1.
        self.alias = alias
        self.secretData = secret_data
        if boolSave == True:
            self.saveACL()


    def save2transfer(self, filename='transfer.txt'):
        public = [self.issuer_pub, self.signature, self.sig]
        toPack = [public, self.secretData]
        transfer = crypto.pack2Save(toPack)
        f = open(filename, 'w+')
        f.write(transfer)
        f.close()
        return 0


    def getAlias(self):
        return self.alias


    def getDenomination(self):
        return self.denomination


    def getSecretData(self):
        return self.secretData


    def getZeta1(self):
        return self.signature[2]


    def getACL(self):
        ''' Returns a coin in a form that can be dealt by acl.py '''
        d = self.denomination
        iss_pub = self.issuer_pub
        sign = self.signature
        sig = self.sig
        numAttr = self.numAttributes
        return ((iss_pub,), numAttr, sign, sig)


    def saveACL(self):
        ''' Appends this particular coin in the db '''

        toPack = [self.issuer_pub, self.signature, self.sig]
        packedData = crypto.marshall(toPack)
        packedSecret = crypto.marshall(self.secretData)

        queryParams = (self.alias, int(self.denomination), packedData, packedSecret)
        dbUser.insert2DB_ACL(queryParams)
        return 0


    @staticmethod
    def loadAC(id):

        coinTemp = dbUser.getACLById(id)
        if coinTemp == -1:
            return -1

        denomination = int(coinTemp[0])
        packedData = coinTemp[1]
        data = crypto.unmarshall(packedData)
        (issuer_pub, signature, sig) = data

        secretPacked = coinTemp[2]
        secretData = crypto.unmarshall(secretPacked)

        coin = ACL(denomination, issuer_pub, signature, sig, secretData,
                   boolSave=False)
        return coin


    @staticmethod
    def addACL(self, coin):
        coin.saveACL()
