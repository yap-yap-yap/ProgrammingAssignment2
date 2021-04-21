package WithCP2;

import AuthUtils.AESKeyUtils;
import AuthUtils.CertificateReader;
import AuthUtils.NonceGenerator;
import AuthUtils.RSAKeyUtils;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Scanner;

public class ClientWithCP2 {

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

			System.out.println("Sending session key...");
			SecretKey session_key = AESKeyUtils.generateKey();
			//System.out.println(session_key);
			byte[] encrypt_session_key_bytes = RSAKeyUtils.encrypt_bytes(session_key.getEncoded(), serverPublicKey);

			toServer.writeInt(5);
			toServer.writeInt(encrypt_session_key_bytes.length);
			toServer.write(encrypt_session_key_bytes);



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

					long start_time = System.nanoTime();

					// Send the filename
					toServer.writeInt(0);
					//System.out.println(input_filename);
					byte[] filename_bytes = input_filename.getBytes();

					byte[] encrypt_filename_bytes = AESKeyUtils.encrypt_bytes(filename_bytes, session_key);

//					System.out.println(filename_bytes);
//					System.out.println(filename_bytes.length);
					toServer.writeInt(encrypt_filename_bytes.length);
					//Thread.sleep(1000);

					toServer.write(encrypt_filename_bytes);
					toServer.flush();

					// Open the file
					//System.out.println("input-files/" + input_filename);
					fileInputStream = new FileInputStream(input_file_path);
					bufferedFileInputStream = new BufferedInputStream(fileInputStream);

					byte [] fromFileBuffer = new byte[128];
					int total_bytes = 0;
					int times_written = 0;
					// Send the file
					for (boolean fileEnded = false; !fileEnded;) {
						numBytes = bufferedFileInputStream.read(fromFileBuffer);
						byte [] encrypt_fromfilebuffer = AESKeyUtils.encrypt_bytes(fromFileBuffer, session_key);

						fileEnded = numBytes < 128;
						//System.out.println("fileEnded: " + fileEnded);
						total_bytes += numBytes;
						times_written++;

						toServer.writeInt(1);
						toServer.writeInt(numBytes); //for communicating length of bytes to write
						toServer.writeInt(encrypt_fromfilebuffer.length); //for communicating length of bytes to read
						toServer.write(encrypt_fromfilebuffer);
						toServer.flush();
					}
					//System.out.println(total_bytes);
					//System.out.println(times_written);

					bufferedFileInputStream.close();
					fileInputStream.close();

					long end_time = fromServer.readLong();
					System.out.println("Time elapsed for sending file: " + (end_time - start_time)/1000000.0 + "ms");


					System.out.println("File sent.\n");


				}catch(Exception e){
					e.printStackTrace();
					continue;
				}
			}

			scanner.close();

			toServer.writeInt(4);
			clientSocket.close();

			System.out.println("Closing connection...");

		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}


}
