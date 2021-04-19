package WithAuthProtocol;

import AuthUtils.*;


import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class ClientWithAuthProtocol {

	public static void main(String[] args) throws Exception {

    	String filename = "100.txt";
    	if (args.length > 0) filename = args[0];

    	String serverAddress = "localhost";
    	if (args.length > 1) filename = args[1];

		X509Certificate CACertificate = CertificateReader.getInstance("security-files/cacsertificate.crt");
		//System.out.println("CA cert: " + CACertificate);

		PublicKey CAPublicKey = CACertificate.getPublicKey();
		//System.out.println("CA public key: " + CAPublicKey);
		//System.out.println();

		String authMessage = "authmessage";

    	int port = 4321;
    	if (args.length > 2) port = Integer.parseInt(args[2]);

		int numBytes = 0;

		Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

    	FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

		long timeStarted = System.nanoTime();

		try {

			System.out.println("Client: Establishing connection to server...");

			// Connect to server and getInstance the input and output streams
			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());

			System.out.println("Client: Requesting signed message for authentication...");
			toServer.writeInt(2);
			toServer.writeUTF(authMessage);
			byte[] signedAuthMessage = new byte[128];
			fromServer.readFully(signedAuthMessage);
			//System.out.println(signedAuthMessage);

			System.out.println("Client: Requesting server certificate...");
			toServer.writeInt(3);
			byte[] serverCertBytes = Base64.getDecoder().decode(fromServer.readUTF());
			X509Certificate serverCertificate = CertificateReader.getInstance(serverCertBytes);

			System.out.println("Client: Verifying server's certificate...");
			try{
				serverCertificate.checkValidity();
				serverCertificate.verify(CAPublicKey);
			}catch(Exception e){
				e.printStackTrace();
				toServer.writeInt(4);
				clientSocket.close();
				return;
			}

			System.out.println("Client: Verifying decrypted message...");
			//System.out.println(signedAuthMessage);
			PublicKey serverPublicKey = serverCertificate.getPublicKey();
			byte[] decryptAuthMessage = RSAKeyUtils.decrypt_bytes(signedAuthMessage, serverPublicKey);
			System.out.println("decrypted message: " + decryptAuthMessage);
			System.out.println("original message: " + authMessage.getBytes());
			if(decryptAuthMessage != authMessage.getBytes()){
				System.out.println("fuck you");
				//toServer.writeInt(4);
				//clientSocket.close();

			}



			System.out.println("Sending file...");

			// Send the filename
			toServer.writeInt(0);
			toServer.writeInt(filename.getBytes().length);
			toServer.write(filename.getBytes());
			//toServer.flush();

			// Open the file
			fileInputStream = new FileInputStream(filename);
			bufferedFileInputStream = new BufferedInputStream(fileInputStream);

	        byte [] fromFileBuffer = new byte[117];

	        // Send the file
	        for (boolean fileEnded = false; !fileEnded;) {
				numBytes = bufferedFileInputStream.read(fromFileBuffer);
				fileEnded = numBytes < 117;

				toServer.writeInt(1);
				toServer.writeInt(numBytes);
				toServer.write(fromFileBuffer);
				toServer.flush();
			}

	        bufferedFileInputStream.close();
	        fileInputStream.close();

			System.out.println("Closing connection...");

		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}
}
