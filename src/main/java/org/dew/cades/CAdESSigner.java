package org.dew.cades;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;

import java.util.Collections;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public 
class CAdESSigner 
{
  protected Certificate certificate;
  protected Key         privateKey;
  
  protected boolean     initCompleted;
  
  public CAdESSigner(String keystoreFile, String password, String alias)
      throws Exception
  {
    this(keystoreFile, password, alias, password);
  }
  
  public CAdESSigner(String keystoreFile, String password, String alias, String passwordKey)
    throws Exception
  {
    if(keystoreFile == null || keystoreFile.length() == 0) {
      return;
    }
    if(password == null || password.length() == 0) {
      return;
    }
    if(alias == null || alias.length() == 0) {
      return;
    }
    if(passwordKey == null || passwordKey.length() == 0) {
      passwordKey = password;
    }
    
    int iFileSep = keystoreFile.indexOf('/');
    if(iFileSep < 0) iFileSep = keystoreFile.indexOf('\\');
    InputStream is = null;
    if(iFileSep < 0) {
      URL url = Thread.currentThread().getContextClassLoader().getResource(keystoreFile);
      if(url == null) return;
      is = url.openStream();
    }
    else {
      is = new FileInputStream(keystoreFile);
    }    
    if(is == null) return;
    
    Security.addProvider(new BouncyCastleProvider());
    
    KeyStore keyStore = null;
    if(keystoreFile.endsWith(".p12")) {
      keyStore = KeyStore.getInstance("PKCS12", "BC");
    }
    else {
      keyStore = KeyStore.getInstance("JKS");
    }
    keyStore.load(is, password.toCharArray());
    
    certificate = keyStore.getCertificate(alias);
    privateKey  = keyStore.getKey(alias, password.toCharArray());
    
    initCompleted = certificate != null && privateKey != null;
  }
  
  public CAdESSigner(Certificate certificate, PrivateKey privateKey)
    throws Exception
  {
    this.certificate = certificate;
    this.privateKey  = privateKey;
    
    Security.addProvider(new BouncyCastleProvider());
    
    initCompleted = certificate != null && privateKey != null;
  }
  
  public
  PrivateKey getPrivateKey()
    throws Exception
  {
    if(privateKey instanceof PrivateKey) {
      return (PrivateKey) privateKey;
    }
    return null;
  }
  
  public
  X509Certificate getX509Certificate()
    throws Exception
  {
    if(certificate instanceof X509Certificate) {
      return (X509Certificate) certificate;
    }
    return null;
  }
  
  public
  String sign(String filePath)
    throws Exception
  {
    String result = filePath + ".p7m";
    
    byte[] plain = readFile(filePath);
    
    byte[] pkcs7 = pkcs7(plain);
    
    writeFile(result, pkcs7);
    
    return result;
  }
  
  @SuppressWarnings("deprecation")
  public
  byte[] pkcs7(byte[] content)
    throws Exception
  {
    if(!initCompleted) return content;
    
    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    byte[] digestedCert = sha256.digest(getX509Certificate().getEncoded());
    
    // Attributo ESSCertID versione 2
    AlgorithmIdentifier aiSha256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
    ESSCertIDv2 essCert1 = new ESSCertIDv2(aiSha256, digestedCert);
    ESSCertIDv2[] essCert1Arr = { essCert1 };
    SigningCertificateV2 scv2 = new SigningCertificateV2(essCert1Arr);
    Attribute certHAttribute = new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2, new DERSet(scv2));
    
    // Tabella Attributi
    ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();
    asn1EncodableVector.add(certHAttribute);
    AttributeTable attributeTable = new AttributeTable(asn1EncodableVector);
    CMSAttributeTableGenerator attrGen = new DefaultSignedAttributeTableGenerator(attributeTable);
    
    CertStore certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(Collections.singletonList(getX509Certificate())));
    
    CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
    generator.addSigner(getPrivateKey(), getX509Certificate(), CMSSignedDataGenerator.DIGEST_SHA256, attrGen, null);
    generator.addCertificatesAndCRLs(certStore);
    
    CMSProcessable cmsProcessable = new CMSProcessableByteArray(content);
    CMSSignedData signedData = generator.generate(cmsProcessable, true, "BC");
    byte[] abPKCS7Signature = signedData.getEncoded();
    
    return abPKCS7Signature;
  }
  
  public
  byte[] extract(byte[] pkcs7)
    throws Exception
  {
    byte[] content = null;
    
    CMSSignedData signedData = new CMSSignedData(pkcs7);
    
    Object oSignedContent = signedData.getSignedContent().getContent();
    if(oSignedContent instanceof byte[]) {
      content = (byte[]) oSignedContent;
    }
    else if(oSignedContent != null) {
      content = oSignedContent.toString().getBytes();
    }
    
    return content;
  }
  
  public
  byte[] readFile(String filePath)
    throws Exception
  {
    InputStream is = null;
    try {
      is = new FileInputStream(filePath);
      int n;
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      byte[] buff = new byte[1024];
      while((n = is.read(buff)) > 0) baos.write(buff, 0, n);
      return baos.toByteArray();
    }
    finally {
      if(is != null) try{ is.close(); } catch(Exception ex) {}
    }
  }
  
  public
  void writeFile(String filePath, byte[] content)
    throws Exception
  {
    FileOutputStream fos = null;
    try {
      fos = new FileOutputStream(filePath);
      fos.write(content);
    }
    finally {
      if(fos != null) try{ fos.close(); } catch(Exception ex) { ex.printStackTrace(); }
    }
  }
}
