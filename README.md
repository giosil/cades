# CAdES

Utility class to sign files width CAdES-BES (CMS Advanced Electronic Signatures) digital signature.

## Example

```java
String lib = "D:\\Main\\bit4xpki.dll";
String pin = "31080808";

CAdESSigner cades = new CAdESSigner(lib, pin);

cades.sign("file.xml");
```

## Build

- `git clone https://github.com/giosil/cades.git`
- `mvn clean install`

## Contributors

* [Giorgio Silvestris](https://github.com/giosil)
