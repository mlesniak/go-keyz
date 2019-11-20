[![Build Status](https://github.com/mlesniak/go-keyz/workflows/Go/badge.svg)](https://github.com/mlesniak/go-keyz/actions?query=workflow%3AGo)

# Overview

This is a simple example of using standard go libraries ("batteries included") to encrypt and decrypt files with
public key cryptography using [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)).

## Compile, Build and Test

Use the standard go commands, i.e.

    go test
    go build

to generate a binary named `keyz`.

## General usage

First, generate your own public and private key pair with

    keyz -k

Your key pair will be saved as `private.key` and `public.key`, respectively. Note that the pair is compatible to the
standard PEM format, i.e. you could also use openssl to generate your key pair using

    openssl genrsa -f4 -out private.key 4096
    openssl rsa -in private.key -outform PEM -pubout -out public.key

Data is always passed from stdin to stdout, hence use pipes correcly. To **encrypt** data, execute

    keyz -e -p <public key name> <input-file >output-file

and to **decrypt** using your private key, use

    keyz -d <encrypted-input-file >plaintext-output-file

## Usage for submitting files over networks using public-key cryptography

`keyz` can be used to submit files over networks using [netcat](https://en.wikipedia.org/wiki/Netcat) without
the necessity to exchange passwords. On the receiving client, start a netcat server on port 1234 which redirects read
data to keyz with

    nc -l 1234|keyz -d

and on the sending client submit a file to the server (here: localhost) with

    keyz -e -p public.key <main.go|nc localhost 1234

## License

As always, the source code is licensed under [Apache license 2.0](https://raw.githubusercontent.com/mlesniak/go-keyz/master/LICENSE).