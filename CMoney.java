import java.security.*;
import javax.crypto.Cipher;
import java.io.*;
import java.nio.file.*;
import java.security.spec.*;
import java.util.*;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;

public class CMoney {

  public int currBlock;

  public CMoney() {
    //figure out the current block
    int count = -1;
    try {
      File dir = new File(System.getProperty("user.dir"));
      String[] files = dir.list();
      for(String file:files) {
        if (file.substring(0, 5).equals("block")) //block_
          count++;
      }
    }
    catch(Exception e) {
      System.out.println(e);
    }
    finally {
      this.currBlock = count;
    }
  }

  public void name() {
    System.out.println("Block Cash");
  }

  public void genesis(String filename) {
    try{
      String content = "This is my genesis block, I hope the rest of this works";
      File file = new File(filename);
      FileWriter fw = new FileWriter(file.getAbsoluteFile());
      BufferedWriter bw = new BufferedWriter(fw);
      bw.write(content);
      bw.close();
    }
    catch(IOException e) {
      System.out.println(e);
    }
  }

  // this converts an array of bytes into a hexadecimal number in
  // text format
  static String getHexString(byte[] b) {
	  String result = "";
	    for (int i = 0; i < b.length; i++) {
	    int val = b[i];
	    if ( val < 0 )
		    val += 256;
	    if ( val <= 0xf )
		    result += "0";
	    result += Integer.toString(val, 16);
	  }
	  return result;
  }

  // this converts a hexadecimal number in text format into an array
  // of bytes
  static byte[] getByteArray(String hexstring) {
	  byte[] ret = new byte[hexstring.length()/2];
	  for (int i = 0; i < hexstring.length(); i += 2) {
	     String hex = hexstring.substring(i,i+2);
	     if ( hex.equals("") )
		     continue;
	     ret[i/2] = (byte) Integer.parseInt(hex,16);
	  }
	  return ret;
  }


  // This will write the public/private key pair to a file in text
  // format.  It is adapted from the code from
  // https://snipplr.com/view/18368/saveload--private-and-public-key-tofrom-a-file/
  static void SaveKeyPair(String filename, KeyPair keyPair) throws Exception {
	  X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
	  PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
	  PrintWriter fout = new PrintWriter(new FileOutputStream(filename));
	  fout.println(getHexString(x509EncodedKeySpec.getEncoded()));
	  fout.println(getHexString(pkcs8EncodedKeySpec.getEncoded()));
	  fout.close();
  }

  // This will read a public/private key pair from a file.  It is
  // adapted from the code from
  // https://snipplr.com/view/18368/saveload--private-and-public-key-tofrom-a-file/
  static KeyPair LoadKeyPair(String filename) throws Exception {
	  // Read wallet
	  Scanner sin = new Scanner(new File(filename));
	  byte[] encodedPublicKey = getByteArray(sin.next());
	  byte[] encodedPrivateKey = getByteArray(sin.next());
	  sin.close();
	  // Generate KeyPair.
	  KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	  X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
	  PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
	  PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
	  PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
	  return new KeyPair(publicKey, privateKey);
  }

  // This will get the SHA-256 hash of a file, and is the same as
  // calling the `sha256sum` command line program
  static String getSignatureOfFile(String filename) throws Exception {
	  byte[] filebytes = Files.readAllBytes(Paths.get(filename));
	  MessageDigest digest = MessageDigest.getInstance("SHA-256");
	  byte[] encodedHash = digest.digest(filebytes);
	  return getHexString(encodedHash);
  }

  public String generate(String filename) {
    String ret = "";
    try{
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
      kpg.initialize(2048);
      KeyPair kp = kpg.generateKeyPair();
      Key pub = kp.getPublic();
      Key pvt = kp.getPrivate();

      try {
        SaveKeyPair(filename, kp);
        byte[] pubKey = kp.getPublic().getEncoded();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] encodedHash = md.digest(pubKey);
        String hash = getHexString(encodedHash);
        ret = hash.substring(0, 16);
      }
      catch(Exception e) {
        System.out.println(e);
      }

    }
    catch(NoSuchAlgorithmException e) {
      System.out.println(e);
    }
    return ret;
  }

  public String address(String filename) {
    try {
      KeyPair kp = LoadKeyPair(filename);
      byte[] pubKey = kp.getPublic().getEncoded();
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] encodedHash = md.digest(pubKey);
      String hash = getHexString(encodedHash);
      return hash.substring(0, 16);

    }
    catch(Exception e) {
      System.out.println(e);
      return "";
    }
  }

  public void fund(String dest, String amnt, String filename) {
    String source = "Mansa Musa"; //source for 'fund' transactions
    try{
      //first create transaction statement
      String from = "From: " + source;
      String to = "To: " + dest;
      String amount = "Amount: " + amnt;
      File file = new File(filename);
      FileWriter fw = new FileWriter(file.getAbsoluteFile());
      BufferedWriter bw = new BufferedWriter(fw);
      bw.write(from + "\n");
      bw.write(to + "\n");
      bw.write(amount);
      bw.close();

      //now transaction record
      File file2 = new File("ledger.txt");
      if (!file2.exists()) {
        FileWriter fw2 = new FileWriter(file2.getAbsoluteFile());
        BufferedWriter bw2 = new BufferedWriter(fw2);
        bw2.write(source + " transfered " + amnt + " to " + dest + "\n");
        bw2.close();
      }
      else {
        FileWriter fw2 = new FileWriter("ledger.txt", true);
        BufferedWriter bw2 = new BufferedWriter(fw2);
        bw2.write(source + " transfered " + amnt + " to " + dest + "\n");
        bw2.close();
      }
    }
    catch(IOException e) {
      System.out.println(e);
    }
  }

  public void transfer(String src, String dest, String amnt, String filename) {
    //get src address
    String source = this.address(src);
    try{
      //first create transaction statement
      String from = "From: " + source + "\n";
      String to = "To: " + dest + "\n";
      String amount = "Amount: " + amnt + "\n";
      String content = from + to + amount;
      File file = new File(filename);
      FileWriter fw = new FileWriter(file.getAbsoluteFile());
      BufferedWriter bw = new BufferedWriter(fw);
      bw.write(content);
      //sign transaction
      KeyPair kp = LoadKeyPair(src);
      Key pvtKey = kp.getPrivate();
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] message = content.getBytes();
      byte[] contentHash = md.digest(message);

      Cipher cipher = Cipher.getInstance("RSA");
      cipher.init(Cipher.ENCRYPT_MODE, pvtKey);
      byte[] signed = cipher.doFinal(contentHash);
      String signature = getHexString(signed);
      bw.write(signature);
      bw.close();
    }
    catch(Exception e) {
      System.out.println(e);
    }
  }

  public String balance(String addr) {
    double bal = 0;
    String f = "block_";
    try {
      //check blocks for balance first
      for (int i = 0; i < currBlock + 1; i++) {
        File block = new File(f + Integer.toString(i) + ".txt");
        FileInputStream fis = new FileInputStream(block);
        BufferedReader br = new BufferedReader(new InputStreamReader(fis));
        String result = "";
        String line = "";
        while((line = br.readLine()) != null){
          //incoming money
          if (line.indexOf(addr) > 0) {
            int amntIndex = line.indexOf("transfered") + 11;
            int amntEndIndex = line.indexOf(' ', amntIndex + 2);
            String amount = line.substring(amntIndex, amntEndIndex);
            bal += Double.parseDouble(amount);
          }
          //outgoing money
          if (line.indexOf(addr) == 0) {
            int amntIndex = line.indexOf("transfered") + 11;
            int amntEndIndex = line.indexOf(' ', amntIndex + 2);
            String amount = line.substring(amntIndex, amntEndIndex);
            bal -= Double.parseDouble(amount);
          }
        }
      }
      //check ledger for balance if it exists
      File ledger = new File("ledger.txt");
      if (ledger.exists()) {
        FileInputStream fis = new FileInputStream(ledger);
        BufferedReader br = new BufferedReader(new InputStreamReader(fis));
        String result = "";
        String line = "";
        while((line = br.readLine()) != null){
          //incoming money
          if (line.indexOf(addr) > 0) {
            int amntIndex = line.indexOf("transfered") + 11;
            int amntEndIndex = line.indexOf(' ', amntIndex + 2);
            String amount = line.substring(amntIndex, amntEndIndex);
            bal += Double.parseDouble(amount);
          }
          //outgoing money
          if (line.indexOf(addr) == 0) {
            int amntIndex = line.indexOf("transfered") + 11;
            int amntEndIndex = line.indexOf(' ', amntIndex + 2);
            String amount = line.substring(amntIndex, amntEndIndex);
            bal -= Double.parseDouble(amount);
          }
        }
      }
    }
    catch(Exception e) {
      System.out.println(e);
    }
    finally {
      return Double.toString(bal);
    }
  }

  public boolean verify(String wallet, String filename) {
    boolean ret = false;
    //for adding to ledger
    String amnt = "";
    String dest = "";
    String source = "";
    String amount = "";
    try {
      File transaction = new File(filename);
      FileInputStream fis = new FileInputStream(transaction);
      BufferedReader br = new BufferedReader(new InputStreamReader(fis));
      String from = br.readLine();
      String to = br.readLine();
      amnt = br.readLine();
      String signature = br.readLine();
      //start with fund requests
      if (from.indexOf("Mansa Musa") >= 0) {
        ret = true;
      }
      //now transfers
      else {
        //first verify signature
        KeyPair kp = LoadKeyPair(wallet);
        Key pubKey = kp.getPublic();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, pubKey);
        byte[] encrypted = getByteArray(signature);
        byte[] bHash = cipher.doFinal(encrypted);
        String sigHash = getHexString(bHash);

        String strMessage = from + "\n" + to + "\n" + amnt + "\n";
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] message = strMessage.getBytes();
        byte[] contentHash = md.digest(message);
        String mesHash = getHexString(contentHash);

        if (!sigHash.equals(mesHash)) {
          ret = false;
        }
        else {
          //now verify balance
          source = from.substring(6, from.length());
          dest = to.substring(4, to.length());
          amount = amnt.substring(8, amnt.length());
          if (Double.parseDouble(this.balance(this.address(wallet))) < Double.parseDouble(amount))
            ret = false;
          else
            ret = true;
        }
      }
      br.close();

      if (ret == true) {
        File ledger = new File("ledger.txt");
        if (!ledger.exists()) {
          FileWriter fw = new FileWriter(ledger.getAbsoluteFile());
          BufferedWriter bw = new BufferedWriter(fw);
          bw.write(source + " transfered " + amount + " to " + dest + "\n");
          bw.close();
        }
        else {
          FileWriter fw = new FileWriter("ledger.txt", true);
          BufferedWriter bw = new BufferedWriter(fw);
          bw.write(source + " transfered " + amount + " to " + dest + "\n");
          bw.close();
        }
      }
    }
    catch(Exception e) {
      System.out.println(e);
    }
    finally {
      return ret;
    }
  }

  public void createBlock(int current) {
    //first get hash of current block
    String prevHash = "";
    try{
      prevHash = getSignatureOfFile("block_" + Integer.toString(current) + ".txt");
    }
    catch(Exception e) {
      System.out.println(e);
    }
    //copy over ledger into block and clear
    try{
      File ledger = new File("ledger.txt");
      FileInputStream fis = new FileInputStream(ledger);
      BufferedReader br = new BufferedReader(new InputStreamReader(fis));
      String result = "";
      String line = "";
      while((line = br.readLine()) != null){
        result = result + line + "\n";
      }
      result = prevHash + "\n" + result;
      ledger.delete();
      String filename = "block_" + Integer.toString(current + 1) + ".txt";
      File file = new File(filename);
      FileWriter fw = new FileWriter(file.getAbsoluteFile());
      BufferedWriter bw = new BufferedWriter(fw);
      bw.write(result);
      bw.close();
      System.out.println("All transactions in ledger moved to " + filename);
    }
    catch(IOException e) {
      System.out.println(e);
    }
  }

  public boolean validate() {
    String f = "block_";
    boolean ret = false;
    try {
      for (int i = 1; i < currBlock + 1; i++) {
        File block = new File(f + Integer.toString(i) + ".txt");
        FileInputStream fis = new FileInputStream(block);
        BufferedReader br = new BufferedReader(new InputStreamReader(fis));
        String topHash = br.readLine();
        if(topHash.equals(getSignatureOfFile(f + Integer.toString(i-1) + ".txt")))
          ret = true;
        else
          ret = false;
      }
    }
    catch(Exception e) {
      System.out.println(e);
    }
    finally {
      return ret;
    }
  }

  public static void main(String[] args) {
    CMoney bc = new CMoney();

    if (args[0].equals("name")) {
      bc.name();
    }

    else if (args[0].equals("genesis")) {
      bc.genesis(args[1]);
      System.out.println("Genesis block created in 'block_0.txt'");
    }

    else if (args[0].equals("generate")) {
      System.out.println("New wallet generated in " + args[1] + " with signature " + bc.generate(args[1]));
    }

    else if (args[0].equals("address")) {
      System.out.println(bc.address(args[1]));
    }

    else if (args[0].equals("fund")) {
      bc.fund(args[1], args[2], args[3]);
      System.out.println(args[1] + " funded with " + args[2]);
    }

    else if (args[0].equals("transfer")) {
      bc.transfer(args[1], args[2], args[3], args[4]);
      System.out.println("Transfered " + args[3] + " from " + args[1] + " to " + args[2] + " with statement " + args[4]);
    }

    else if (args[0].equals("balance")) {
      System.out.println("Balance of wallet " + args[1] + ": " + bc.balance(args[1]));
    }

    else if (args[0].equals("verify")) {
      if (bc.verify(args[1], args[2]))
        System.out.println("The transaction in file '" + args[2] + "' with wallet '" + args[1] + "' is valid and was written to the ledger" );
      else
        System.out.println("The transaction in file '" + args[2] + "' with wallet '" + args[1] + "' is not valid and was not written to the ledger" );
    }

    else if (args[0].equals("createblock")) {
      bc.createBlock(bc.currBlock);
    }

    else if (args[0].equals("validate")) {
      if (bc.validate())
        System.out.println("The entire blockchain is valid");
      else
        System.out.println("The entire blockchain is not valid");
    }
  }

}
