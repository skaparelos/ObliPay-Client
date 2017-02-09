# FAQ

## What is ObliPay (in plain English)
ObliPay is a service that allows you to transact money with your friend (or any merchant), without anyone (not even the service) except your friend learning the transacted amount, as well as who transacted with whom.

## Why use ObliPay over a cryptocurrency like Bitcoin?
Bitcoin does not protect your privacy. Other cryptocurrencies do, but the problem is that their valuation fluctuates a lot, which can result to loss of money. ObliPay can be used with any currency that you trust.

## Where is my money stored?
Your money is stored locally at your computer. Like cash in your wallet.

## How does it work?
You deposit some amount of money (in any currency) using the website and in exchange you get a credential (think of it as a coin) that corresponds to that amount. That credential has some cryptographic properties, two of which are unforgeability and unlinkability. That credential that you get is stored locally in your computer. Now that you have that credential (or many others) you can do one of the following with it:
-Split: one credential to two credentials such that the sum of their values is equal to the value of the credential you had before.
-Combine: two credentials to one, such that the value of the newly formed credential is equal to the sum of the value of the two.
-Spend: transfer a credential to a friend of yours, effectively transferring money.
-Withdraw: open a credential to the service and have the service give you back the amount of money that this credential corresponds to.

## Can you give a real-life example scenario of how it works? 
#TODO
Assume Bob wants to transfer money to Alice, and he wants to protects his privacy, i.e. he doesn't want anyone else to know 

## Doesn't my IP reveal my identity?
If the service gets compromised, your IP might harm your privacy. Therefore, you should use an anonymous channel, like Tor.

## Why have a service?
We need to make sure that money is not minted in an arbitrary fashion and have someone check for double spending.

## What ObliPay is NOT:
* It's not a currency.
* It's not a typical e-cash scheme.

## Where can I read more about it?
Link to thesis and short paper.

### Deleting sqlite DB
```
delete from table_name; // delete table data
vacuum; // delete unused space
delete from sqlite_sequence where name='table_name'; // resets ID to 0
```

