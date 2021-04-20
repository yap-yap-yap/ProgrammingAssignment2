package WithAuthProtocol;

import AuthUtils.*;


import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Scanner;

public class ClientWithAuthProtocol {

	public static void main(String[] args) throws Exception {

    	//String filename = "100.txt";
    	//if (args.length > 0) filename = args[0];

    	String serverAddress = "localhost";
    	//if (args.length > 1) filename = args[1];

		X509Certificate CACertificate = CertificateReader.getInstance("security-files/cacsertificate.crt");
		//System.out.println("CA cert: " + CACertificate);

		PublicKey CAPublicKey = CACertificate.getPublicKey();
		//System.out.println("CA public key: " + CAPublicKey);
		//System.out.println();

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
			String authMessage = NonceGenerator.get(8);
			//System.out.println("original nonce: " + authMessage);
			toServer.writeInt(2);
			toServer.writeUTF(authMessage);
			int signedAuthMessageLength = fromServer.readInt();
			byte[] signedAuthMessage = new byte[signedAuthMessageLength];
			fromServer.readFully(signedAuthMessage, 0, signedAuthMessageLength);
			//System.out.println("encrypted nonce: " + signedAuthMessage);

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
				System.out.println("Server cannot be trusted. Closing connection...");
				toServer.writeInt(4);
				clientSocket.close();
				return;
			}

			System.out.println("Client: Verifying decrypted message...");
			//System.out.println(signedAuthMessage);
			PublicKey serverPublicKey = serverCertificate.getPublicKey();
			byte[] decryptAuthMessage = RSAKeyUtils.decrypt_bytes(signedAuthMessage, serverPublicKey);
			//System.out.println("decrypted message: " + new String(decryptAuthMessage));
			//System.out.println("original message: " + authMessage);
			if(!authMessage.equals(new String(decryptAuthMessage))){
				System.out.println("Server cannot be trusted. Closing connection...");
				toServer.writeInt(4);
				clientSocket.close();
				return;
			}

			System.out.println("Connection authenticated.");
			Scanner scanner = new Scanner(System.in);
			String input_filename = "";

			while(!input_filename.equals("exit()")){
				try{
					System.out.println("Enter filename of desired file to send. Enter exit() to close connection.");
					input_filename = scanner.nextLine();
					String input_file_path = "input-files/" + input_filename;
					if(input_filename.equals("exit()")){
						continue;
					}
					if(!new File(input_file_path).exists()){
						System.out.println("File must be in directory ./input-files/.");
						continue;
					}
					System.out.println("Sending file...");

					// Send the filename
					toServer.writeInt(0);
					toServer.writeInt(input_filename.getBytes().length);
					toServer.write(input_filename.getBytes());
					//toServer.flush();

					// Open the file
					//System.out.println("input-files/" + input_filename);
					fileInputStream = new FileInputStream(input_file_path);
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

				}catch(Exception e){
					e.printStackTrace();
					continue;
				}
			}



			toServer.writeInt(4);
			clientSocket.close();

			System.out.println("Closing connection...");

		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}


}
