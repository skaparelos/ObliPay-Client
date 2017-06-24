import sqlite3
import os.path
import sys
import os

#TODO check for SQLinjections

'''
    This file is responsible for handling database interactions.
    The database contains one table, the 'acl' table that stores acls.
'''

''' ############################################################ '''
''' General DB Operations '''

def createDBTables(conn, cur):
    ''' Create the DB tables '''

    retStatus = 0
    error = ''
    try:
        cur.execute("""CREATE TABLE "acl" (
                      "id" INTEGER PRIMARY KEY AUTOINCREMENT ,
                      "alias" varchar(50) NULL DEFAULT '',
                      "denomination" INTEGER NOT NULL DEFAULT '',
                      "packed_data" varchar(1000) NOT NULL DEFAULT '',
                      "secret_data" varchar(250) NOT NULL DEFAULT ''
                    ); """ )

        conn.commit()
    except:
        error = "Error while creating tables locally:"
        error = "".join([error, str(sys.exc_info()[0]), str(sys.exc_info()[1])])
        retStatus = -1
        print error

    return (retStatus, error)


def getDBconnection():
    ''' Connects to the database and returns an instance of the connection '''
    filename = 'wallet.db'
    #check if the database already exists or tables have to be created
    fileExists = os.path.isfile(filename)

    conn = sqlite3.connect(filename)
    cursor = conn.cursor()

    if fileExists == False:
        createDBTables(conn, cursor)

    return conn, cursor


db = getDBconnection()


''' ############################################################ '''
''' ACL Operations '''

def insert2DB_ACL(queryParams):
    conn, cur = db
    returnStatus = 0

    try:
        cur.execute("""INSERT INTO acl (alias,denomination,packed_data,secret_data) 
                    VALUES (?,?,?,?)""", queryParams)
        conn.commit()
    except:
        returnStatus = -1
        conn.rollback()
        e = sys.exc_info()[0]
        e1 = sys.exc_info()[1]
        print e,e1

    #conn.close()
    return returnStatus


def printACs():
    conn, cur = db
    cur.execute(""" SELECT id,alias,denomination FROM acl """)

    print "------- Coins: -------"
    for r in cur.fetchall():
        (id, alias, denom) = r
        print str(id) + ") " + alias + "->\tValue:" + str(denom) 
    return 0


def getACById(id):
    assert type(id) == type(1)
    (conn, cur) = db
    param = (str(id),)
    cur.execute(""" SELECT denomination,packed_data,secret_data FROM acl WHERE id = (?)""", param)
    coin = cur.fetchone()
    if coin is None:
        raise Exception("Coin id doesn't exist.")
    return coin


def invalidateACL(id):
    conn, cur = db
    try:
        param = (str(id), )
        cur.execute("""DELETE FROM acl WHERE id = ? """, param )
        conn.commit()
    except:
        conn.rollback()
        #conn.close()
        return -1
    return 0


def getTotalBalance():
    conn, cur = db
    cur.execute(""" SELECT SUM(denomination) FROM acl """)
    totalBalance = cur.fetchone()
    #conn.close()
    return totalBalance[0]


def getLastACLid(numofIds):
    conn, cur = db
    
    if numofIds == 1:
        cur.execute("""SELECT id FROM acl ORDER BY id DESC LIMIT 1 """)
        (ret,) = cur.fetchone()

    if numofIds == 2:
        cur.execute("""SELECT id FROM acl ORDER BY id DESC LIMIT 2 """)
        (id1,), (id2,) = cur.fetchall()
        ret = id1, id2

    return ret 


#def deleteAllACL():
#    conn, cur = getDBconnection()
#    cur.execute("""DELETE FROM acl""")
#    conn.close()
#    return 0
