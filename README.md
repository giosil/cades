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

## Build

- `git clone https://github.com/giosil/cades.git`
- `mvn clean install`

## Contributors

* [Giorgio Silvestris](https://github.com/giosil)
