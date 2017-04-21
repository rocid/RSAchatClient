import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;

import javax.crypto.Cipher;

public class ClientMain {
	public static byte[] testRSA_encrypt(Key key, String text) throws Exception{
		Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(text.getBytes()); 
        return cipherText;
	}
	// private key로 복호화 하는 함수
	public static byte[] testRSA_decrypt(Key key, byte[] cipherText) throws Exception{
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plainText = cipher.doFinal(cipherText);
        return plainText;
	}
	// public key로 암호화 하는 함수
	public static Key[] generateRSAKey() throws Exception{
		Key[] key = new Key[2];
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        Key publicKey = keyPair.getPublic(); 
        Key privateKey = keyPair.getPrivate(); 
        
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
        RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
        /*
        System.out.println("public key modulus(" + publicKeySpec.getModulus() + 
        		") exponent(" + publicKeySpec.getPublicExponent() + ")");
        System.out.println("private key modulus(" + privateKeySpec.getModulus() + 
        		") exponent(" + privateKeySpec.getPrivateExponent() + ")");
        */
        key[0] = publicKey;
        key[1] = privateKey;
        
        return key;
	}
	// public key와 private key를 생성하는 함수
	
	// byte[] to hex
	public static String byteArrayToHex(byte[] ba) {
		if (ba == null || ba.length == 0) {
	        return null;
	    }
		 
	    StringBuffer sb = new StringBuffer(ba.length * 2);
	    String hexNumber;
	    for (int x = 0; x < ba.length; x++) {
	        hexNumber = "0" + Integer.toHexString(0xff & ba[x]);
		 
	        sb.append(hexNumber.substring(hexNumber.length() - 2));
	    }
	    return sb.toString();
	} 
	
	// hex to byte[]
	public static byte[] hexToByteArray(String hex) {
	    if (hex == null || hex.length() == 0) {
	        return null;
	    }

	    byte[] ba = new byte[hex.length() / 2];
	    for (int i = 0; i < ba.length; i++) {
	        ba[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
	    }
	    return ba;
	}
	
	public static void main(String[] args) throws Exception {
		
		// TODO Auto-generated method stub
		Key[] client_rsaKey = generateRSAKey();
		Key client_publicKey = client_rsaKey[0];
		Key client_privateKey = client_rsaKey[1];
		// Client의 public, private key 생성
		
		Scanner scan = new Scanner(System.in);
		
		String server_addr;
		int server_port;
		String client_addr;
		int client_port;
		String gateway_addr;
		int gatewayInterface = 3000;
		
		System.out.print("Server IP : ");
		server_addr = scan.nextLine();
		
		System.out.print("Server Port : ");
		server_port = Integer.parseInt(scan.nextLine());
		//server_port = 3003; 
				
		System.out.print("Gateway IP : ");
		gateway_addr = scan.nextLine();
		
		/*connect*/		
		Socket socket = new Socket(gateway_addr,gatewayInterface);		
		ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());				
		ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
				
		client_addr = socket.getLocalAddress().toString();
		client_port = socket.getLocalPort();
		
		System.out.println("\nConnect message");
		Message send_message = new Message(server_addr,server_port,
				client_addr, client_port, "connect", null, null);
		oos.reset();
		oos.writeObject(send_message);
		
		send_message = new Message(server_addr,server_port,
				client_addr, client_port,"data",null,client_publicKey);
		oos.reset();
		oos.writeObject(send_message);
		// client public key를 server에게 전송
		
		Message recv_message = (Message)ois.readObject();
		Key server_publicKey = recv_message.public_key;
		// server에서 server public key를 받음
		
		System.out.print("Send Data (>\"exit\" => disconnect)");
		/*send data*/
		while(true){
			System.out.print(">");
			String str = scan.nextLine();
			if(str.equals("exit")) break;
			
			byte[] cipherText = testRSA_encrypt(server_publicKey,str); // 입력한 문장을 server의 public key로 암호화
			//System.out.println("rsa>"+byteArrayToHex(cipherText));// 암호화된 문장 확인
			send_message = new Message(server_addr,server_port,
					client_addr, client_port,"data",byteArrayToHex(cipherText), null); // 암호화된 문장을 전송
			oos.reset();
			oos.writeObject(send_message);
			
			recv_message = (Message)ois.readObject();
			//System.out.println("rsa>"+recv_message.msg);// 암호화된 문장 확인
			System.out.println("server>"+
					new String(testRSA_decrypt(client_privateKey, hexToByteArray(recv_message.msg)))); // public private key로 복호화
		}
		
		/*disconnect*/
		send_message = new Message(server_addr,server_port,client_addr, client_port,"dsconnect",null, null);
		oos.reset();
		oos.writeObject(send_message);
		
		for(int i=0;i<5;i++){
			System.out.println("wait "+(5-i));
			Thread.sleep(1000);
		}
		ois.close();
		socket.close();
		System.out.println("disconnect");
	}		
}
