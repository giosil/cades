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
    String library = "";
    // String library = "D:\\Main\\bit4xpki.dll";
    String pin     = "31080808";
    
    CAdESSigner cades = new CAdESSigner(library, pin);
    
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
