#!/usr/bin/env python

import user
import time
from sys import argv

script, tries = argv

tries = int(tries)

#Split ACL test
t0 = time.time()

for i in range(0, tries):
	user.deposit(True)

t1 = time.time()
avg = (t1-t0)/tries
print "Deposit Average time = ", avg
