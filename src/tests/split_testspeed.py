#!/usr/bin/env python

import user
import time
from sys import argv

script, tries = argv

tries = int(tries)

#Split ACL test
coin = user.deposit(True)
t0 = time.time()
user.testSplitACL(coin, tries)
t1 = time.time()
avg = (t1-t0)/tries
print "splitACL Average time = ", avg
print "Communication + server time = ", user.commServerTime/tries
print "proofTime =", user.proofTime/tries
