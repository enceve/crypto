## The *crypto* package

### Introduction

The `crypto` package implements some additional cryptographic functionality, currently not supported by the standard or additional [golang packages](https://golang.org/pkg/ "Offical golang packages").
Check out the documentation at [godoc] (https://godoc.org/github.com/EncEve/crypto "GoDoc").

Notice:
This code should currently NOT used in productive environments!
The public API is not stable and backward compatibility is currently NOT guaranteed.

This cryptographic functionality can be:

* cryptographic primitives like block / stream ciphers, hash functions etc.

* cryptographic protocols

* general useful cryptographic functions

This repository should not replace or somehow compete with the [golang-crypto packages](https://godoc.org/golang.org/x/crypto "Additional golang crypto packages"). Rather, this package should supplement the official and additional golang cryptographic.

### Aim

The aim of this project / repository is a powerful, flexible and easy to use cryptographic library,
which can be easily integrated into Go applications.  

### Contribute

First of all: **Contributions are welcome!**
 
If you have an idea or found a bug - please raise an issue. If you want to add functionality - as usual on github send a pull request.
