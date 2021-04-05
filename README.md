# CAdES

Utility class to sign files width CAdES-BES (CMS Advanced Electronic Signatures) digital signature.

The library provides the following classes:

- `org.dew.cades.CAdESSigner` - CAdES Signer by keystore
- `org.dew.cades.CAdESSignerSC` - CAdES Signer by smartcard

## Example

```java
CAdESSigner cades = new CAdESSigner("keystore.jks", "password", "selfsigned");

cades.sign("file.xml");
```

## Manage certificates using Java Keytool

Generate a Self Signed Certificate

`keytool -genkey -keyalg RSA -alias selfsigned -keystore keystore.jks -storepass password -validity 365 -keysize 2048`

Convert keystore from JKS to PKCS12

`keytool -importkeystore -srckeystore keystore.jks -destkeystore keystore.p12 -deststoretype PKCS12 -srcalias selfsigned -srcstorepass password -deststorepass password -destkeypass password`

List certificates

`keytool -list -keystore keystore.jks -storepass password`

View certificates

`keytool -list -rfc -alias selfsigned -keystore keystore.jks -storepass password`

Export certificates

`keytool -export -alias selfsigned -keystore keystore.jks -storepass password -file selfsigned.cer`

Import certificates

`keytool -import -file test.pem -alias test -keystore keystore.jks -storepass password`

Delete certificates

`keytool -delete -alias test -keystore keystore.jks -storepass password`

## Manage private key and certificates using openssl

Create keystore.p12 in PKCS12 format

`openssl pkcs12 -export -in cert.pem -inkey pkey.pem -name shared > keystore.p12`

View certificates in keystore.p12

`openssl pkcs12 -in keystore.p12 -nokeys -info -passin pass:password`

Export certificates from keystore.p12

`openssl pkcs12 -in keystore.p12 -nokeys -out cert.pem`

Export private key from keystore.p12

`openssl pkcs12 -in keystore.p12 -nodes -nocerts -out pkey.pem`

Convert private key in RSA private key

`openssl rsa -in pkey.pem -out rkey.pem`

Convert keystore from PKCS12 to JKS

`keytool -importkeystore -srckeystore keystore.p12 -srcstoretype pkcs12 -srcalias shared -destkeystore keystore.jks -deststoretype jks -deststorepass password -destalias shared`

## Build

- `git clone https://github.com/giosil/cades.git`
- `mvn clean install`

## Contributors

* [Giorgio Silvestris](https://github.com/giosil)
