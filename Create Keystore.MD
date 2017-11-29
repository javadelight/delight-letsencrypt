

1. Convert to p12:

openssl pkcs12 -export -in output/domain-chain.crt -inkey output/domain.key -out output/server.p12 -name cert -CAfile ca.crt -caname root

2. Create new Keystore with Keystore explorer

3. Import p12 file

4. Import CSR reply (right click on KEY).

5. Import domain, by going to Examine file and then clicking Import