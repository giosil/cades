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

`"%JAVA_HOME%"\bin\keytool -genkey -keyalg RSA -alias selfsigned -keystore keystore.jks -storepass password -validity 365 -keysize 2048`

List certificates

`"%JAVA_HOME%"\bin\keytool -list -keystore keystore.jks -storepass password`

View certificates

`"%JAVA_HOME%"\bin\keytool -list -rfc -alias selfsigned -keystore keystore.jks -storepass password`

Export certificates

`"%JAVA_HOME%"\bin\keytool -export -alias selfsigned -keystore keystore.jks -storepass password -file selfsigned.cer`

Import certificates

`"%JAVA_HOME%"\bin\keytool -import -file test.pem -alias test -keystore keystore.jks -storepass password`

Delete certificates

`"%JAVA_HOME%"\bin\keytool -delete -alias test -keystore keystore.jks -storepass password`

## Build

- `git clone https://github.com/giosil/cades.git`
- `mvn clean install`

## Contributors

* [Giorgio Silvestris](https://github.com/giosil)
