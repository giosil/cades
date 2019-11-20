package org.dew.cades;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;

import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;

import java.util.Collections;
import java.util.Enumeration;

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

public class CAdESSigner {
	
	protected String providerName;
	protected String library;
	
	protected InputStream providerConfig;
	protected char[]      passwordKeystore;
	protected KeyStore    keystore;
	
	protected String      alias_Auth;
	protected Certificate certificate_Auth;
	protected Key         privateKey_Auth;
	
	protected String      alias_Sign;
	protected Certificate certificate_Sign;
	protected Key         privateKey_Sign;
	
	public CAdESSigner(String library, String pin)
		throws Exception
	{
		this(library, "smartcard", pin);
	}
	
	@SuppressWarnings("restriction")
	public CAdESSigner(String library, String providerName, String pin)
		throws Exception
	{
		this.providerName   = providerName;
		this.library        = library;
		
		if(library == null || library.length() == 0) {
			return;
		}
		
		this.providerConfig = new ByteArrayInputStream(("name=" + providerName + "\nlibrary=" + library + "\n").getBytes());
		
		Provider providerPKCS11 = new sun.security.pkcs11.SunPKCS11(providerConfig);
		Security.addProvider(providerPKCS11);
		
		this.passwordKeystore = pin.toCharArray();
		
		keystore = KeyStore.getInstance("PKCS11");
		keystore.load(null, passwordKeystore);
		
		Enumeration<String> aliases = keystore.aliases();
		if(aliases.hasMoreElements()) {
			alias_Auth = aliases.nextElement();
		}
		if(aliases.hasMoreElements()) {
			alias_Sign = aliases.nextElement();
		}
		if(alias_Sign == null) alias_Sign = alias_Auth;
		
		certificate_Auth = keystore.getCertificate(alias_Auth);
		privateKey_Auth  = keystore.getKey(alias_Auth, passwordKeystore);
	}
	
	public
	PrivateKey getPrivateKeyAuth()
		throws Exception
	{
		if(privateKey_Auth instanceof PrivateKey) {
			return (PrivateKey) privateKey_Auth;
		}
		return null;
	}
	
	public
	X509Certificate getX509CertificateAuth()
		throws Exception
	{
		if(certificate_Auth instanceof X509Certificate) {
			return (X509Certificate) certificate_Auth;
		}
		return null;
	}
	
	public
	PrivateKey getPrivateKeySign()
		throws Exception
	{
		if(privateKey_Sign instanceof PrivateKey) {
			return (PrivateKey) privateKey_Sign;
		}
		if(alias_Sign == null || keystore == null) return null;
		privateKey_Sign = keystore.getKey(alias_Sign, passwordKeystore);
		if(privateKey_Sign instanceof PrivateKey) {
			return (PrivateKey) privateKey_Sign;
		}
		return null;
	}
	
	public
	X509Certificate getX509CertificateSign()
		throws Exception
	{
		if(certificate_Sign instanceof X509Certificate) {
			return (X509Certificate) certificate_Sign;
		}
		if(alias_Sign == null || keystore == null) return null;
		certificate_Sign = keystore.getCertificate(alias_Sign);
		if(certificate_Sign instanceof X509Certificate) {
			return (X509Certificate) certificate_Sign;
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
		if(library == null || library.length() == 0) {
			return content;
		}
		
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		byte[] digestedCert = sha256.digest(getX509CertificateSign().getEncoded());
		
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
		
		CertStore certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(Collections.singletonList(getX509CertificateSign())));
		
		CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
		generator.addSigner(getPrivateKeySign(), getX509CertificateSign(), CMSSignedDataGenerator.DIGEST_SHA256, attrGen, null);
		generator.addCertificatesAndCRLs(certStore);
		
		CMSProcessable cmsProcessable = new CMSProcessableByteArray(content);
		CMSSignedData signedData = generator.generate(cmsProcessable, true, "SunPKCS11-" + providerName);
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
