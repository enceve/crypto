[![Build Status](https://api.travis-ci.org/enceve/crypto.svg?branch=master)](https://api.travis-ci.org/enceve/crypto)
[![Godoc Reference](https://godoc.org/github.com/enceve/crypto?status.svg)](https://godoc.org/github.com/enceve/crypto)
[![Go Report](https://goreportcard.com/badge/github.com/enceve/crypto)](https://goreportcard.com/report/github.com/enceve/crypto)

## The *crypto* package

**Notice**:
The public API is not stable and backward compatibility is currently not guaranteed.
This code should currently NOT used in productive environments!

### Introduction

The `crypto` package implements some additional cryptographic functionality, currently not supported by the standard or additional [golang packages](https://golang.org/pkg/ "offical golang packages").  
This repository should not replace or somehow compete with the [golang crypto packages](https://godoc.org/golang.org/x/crypto "Additional golang crypto packages"). Rather, this package should supplement the official and additional golang cryptographic.

**Currently implemented**:
- The [BLAKE2b and BLAKE2s](https://blake2.net/ "offical BLAKE2 site") hash functions.
- The [Camellia](https://tools.ietf.org/html/rfc3713 "RFC 3713") block cipher.
- The [ChaCha20](https://tools.ietf.org/html/rfc7539 "RFC 7539") stream cipher.
- The [CMac](https://tools.ietf.org/html/rfc4493 "RFC 4493") message authentication code (OMAC1).
- The [HC-128 and HC-256](https://en.wikipedia.org/wiki/HC-256 "Wikipedia") stream ciphers
- The [Poly1305](https://tools.ietf.org/html/rfc7539 "RFC 7539") message authentication code.
- The [Serpent](https://www.cl.cam.ac.uk/~rja14/serpent.html "offical Serpent site") block cipher.
- The [SipHash](https://131002.net/siphash/ "offical SipHash site") message authentication code.
- The [Skein](http://skein-hash.info/ "offical Skein site") hash function.
- The [Threefish](http://skein-hash.info/ "offical Skein/Threefish site") tweakable block cipher.
- The [Diffie-Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange "Wikipedia") and [ECDH](https://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman "Wikipedia") key exchange.
- The [EAX](https://en.wikipedia.org/wiki/EAX_mode "Wikipedia") AEAD block cipher mode.
- Some [Padding](https://en.wikipedia.org/wiki/Padding_%28cryptography%29 "Wikipedia") schemes for block ciphers.

### Aim

The aim of this project / repository is a powerful, flexible and easy to use cryptographic library,
which can be easily integrated into Go applications.  

### Installation

Install in your GOPATH: `go get -u github.com/enceve/crypto`  
Install Dependencies: `go get -u golang.org/x/crypto`  

### Contribute

First of all: **Contributions are welcome!**
 
If you have an idea or found a bug - please raise an issue. If you want to add functionality - as usual on github send a pull request.
