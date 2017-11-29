#!/bin/bash


openssl pkcs12 -export -in output/domain-chain.crt -inkey output/domain.key -out output/server.p12 -name cert -CAfile ca.crt -caname root

