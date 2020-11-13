package org.dew.cades;

import java.io.File;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class TestCAdES extends TestCase {
  
  public TestCAdES(String testName) {
    super(testName);
  }
  
  public static Test suite() {
    return new TestSuite(TestCAdES.class);
  }
  
  public 
  void testApp() 
    throws Exception 
  {
    check_CAdESSigner_Keystore();
  }
  
  public 
  void check_CAdESSigner_Keystore() 
    throws Exception 
  {
    CAdESSigner cades = new CAdESSigner("keystore.jks", "password", "selfsigned");
    
    String folderPath = System.getProperty("user.home") + File.separator + "Desktop";
    File folder = new File(folderPath);
    if(!folder.exists()) folder.mkdirs();
    
    byte[] pkcs7 = cades.pkcs7("test".getBytes());
    
    if(pkcs7 == null) {
      System.out.println("cades.pkcs7(\"test\".getBytes()) -> null");
    }
    else {
      System.out.println("cades.pkcs7(\"test\".getBytes()) -> [" + pkcs7.length + "]");
    }
  }
  
  public 
  void check_CAdESSigner_SmartCard() 
    throws Exception 
  {
    String library = "";
    // String library = "D:\\Main\\bit4xpki.dll";
    String pin     = "31080808";
    
    CAdESSignerSC cades = new CAdESSignerSC(library, pin);
    
    String folderPath = System.getProperty("user.home") + File.separator + "Desktop";
    File folder = new File(folderPath);
    if(!folder.exists()) folder.mkdirs();
    
    String filePath = folderPath + File.separator + "test_cades.txt";
    
    File file = new File(filePath);
    if(!file.exists()) {
      cades.writeFile(filePath, "test".getBytes());
    }
    System.out.println("File to sign: " + filePath);
    
    String signedFile = cades.sign(filePath);
    System.out.println("Signed file: " + signedFile);
  }
}
