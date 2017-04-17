minicert
========

An experiment in making a PKI-like thing that is as minimal as possible.
Things that have been have removed relative to X.509 / [RFC
5280](https://tools.ietf.org/html/rfc5280):

* Algorithm agility (we might want this back)
* Serial numbers
* Most variable-length fields
* Extensions
* In particular, name constraints
* Any notion of [X.400](https://en.wikipedia.org/wiki/X.400) directory names
* Any names for CAs (chaining is by key only)
* Any information about revocation
