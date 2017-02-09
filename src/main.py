#!/usr/bin/env python
import user

def printMenuOptions():
    print '#' * 20
    print ' 1) Show wallet'
    print ' 2) See Total Balance'
    print ' 3) Mint ACL'
    # print ' 4) Spend ACL'
    print ' 4) Split ACL'
    print ' 5) Combine ACL'
    print ' 6) Spend ACL'
    print '-1) Exit'


def mainMenu():
    choice = 0

    while choice != "-1":

        printMenuOptions()
        choice = raw_input("Enter:")

        if choice == "1":
            user.showWallet()

        elif choice == "2":
            user.seeTotalBalance()

        elif choice == "3":
            user.deposit()

        # elif choice == "4":
        #	user.verifyACL()

        elif choice == "4":
            user.protocolSetup("split")
        # user.splitACL()

        elif choice == "5":
            user.protocolSetup("combine")
        # user.combineACL()

        elif choice == "6":
            user.protocolSetup("spend")

        # elif choice == "7":
        #	user.deleteAllACL()


if __name__ == '__main__':
    mainMenu()
