# delight-letsencrypt

This library creates a Java [keystore](https://docs.oracle.com/javase/7/docs/api/java/security/KeyStore.html) 
from a new Let's Encrypt certificate.

**Important** If you use this library to obtain certificates from Lets Encrypt, you need to agree to their [Agreements](https://letsencrypt.org/repository/).  

## Requirements

- The target directory must exist before running the command.
- The app **must** be run on the server which is mapped to the domain. No other web server (e.g. Apache, Nginx, Tomcat) should be running during the time of execution.
- The Java application running the app must have sufficient privileges to bind to port 80 (you will probably have to run it with `sudo`).
- `keytool` and `openssl` must be installed.
- The tool only work on Linux.

## Usage (CLI)

Do all the following on the server which is mapped to the domain name you want to get the certificate for.

First grab the latest release from [Releases](https://github.com/javadelight/delight-letsencrypt/releases):

```
wget https://github.com/javadelight/delight-letsencrypt/releases/download/v0.0.4/delight-letsencrypt-0.0.4.jar
```

Then create the output directory:

```
mkdir output
```

Finally, run the command replacing `my.domain.com` with your own domain name.

```
sudo java -jar delight-letsencrypt-0.0.4.jar my.domain.com
```

You can now find the keystore with the SSL certificate in:

```
output/server.jks
```

The password for the store is **password**.

## Usage (Java API)

Simply specify the domain for which you require the certificate and everything else will happen automagically!

```
GetSSLCertificate.generateCertificate("www.mydomain.com", new File("cert"));
```

The resulting keystore will be stored in the location `cert/server.jks`.






