package WithCP2;

import AuthUtils.AESKeyUtils;
import AuthUtils.CertificateReader;
import AuthUtils.PrivateKeyReader;
import AuthUtils.RSAKeyUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class ServerWithCP2 {

	public static void main(String[] args) throws Exception {

		PrivateKey privateKey = PrivateKeyReader.get("security-files/private_key.der");
		//System.out.println("private key: " + privateKey);

		//PublicKey publicKey = PublicKeyReader.get("security-files/public_key.der");

		X509Certificate serverCertificate = CertificateReader.getInstance("security-files/certificate_1004570.crt");
		//System.out.println("server certificate: " + serverCertificate);



		int port = 4321;
    	if (args.length > 0) port = Integer.parseInt(args[0]);

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;

		File output_dir = new File("received-files");
		if(!output_dir.exists()){
			output_dir.mkdir();
		}

		try {
			welcomeSocket = new ServerSocket(port);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());
			int times_read = 0;

			SecretKey session_key = null;


			while (!connectionSocket.isClosed()) {

				int packetType = fromClient.readInt();


				// If the packet is sending a authentication message to be signed
				if (packetType == 2){
					System.out.println("Server: Sending signed message to client...");

					String authMessage = fromClient.readUTF();
					//System.out.println("original nonce: " + authMessage);
					byte[] encryptAuthMessage = RSAKeyUtils.encrypt_bytes(authMessage.getBytes(), privateKey);
					//System.out.println("encrypted nonce: " + encryptAuthMessage);
					toClient.writeInt(encryptAuthMessage.length); //so that client can generate a byte array of suitable length
					toClient.write(encryptAuthMessage);
				}

				// If the packet is requesting the server's certificate
				if (packetType == 3){
					System.out.println("Server: Sending certificate to client...");
					toClient.writeUTF(Base64.getEncoder().encodeToString(serverCertificate.getEncoded()));
				}

				if (packetType == 4){
					System.out.println("Closing connection...");
					fromClient.close();
					toClient.close();
					connectionSocket.close();
				}

				// If the packet is transferring the session AES key
				if (packetType == 5){
					int numBytes = fromClient.readInt();
					byte [] encrypt_session_key_bytes = new byte[numBytes];
					fromClient.readFully(encrypt_session_key_bytes, 0, numBytes);

					byte [] session_key_bytes = RSAKeyUtils.decrypt_bytes(encrypt_session_key_bytes, privateKey);

					session_key = new SecretKeySpec(session_key_bytes, "AES");
					//System.out.println(session_key);
				}

				// If the packet is for transferring the filename
				if (packetType == 0) {

					System.out.println("Receiving file...");

					int numBytes = fromClient.readInt();
					//System.out.println("this is the size of the filename: " + numBytes);
					byte [] encrypt_filename = new byte[numBytes];
					// Must use read fully!
					// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
					fromClient.readFully(encrypt_filename, 0, numBytes);

					byte[] filename = AESKeyUtils.decrypt_bytes(encrypt_filename, session_key);

					System.out.println("Saving to: " + "received-files/recv_"+new String(filename, 0, filename.length));
					fileOutputStream = new FileOutputStream("received-files/recv_"+new String(filename, 0, filename.length));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				}

				// If the packet is for transferring a chunk of the file
				if (packetType == 1) {
					//System.out.println("receiving block");
					int numBytes = fromClient.readInt();
					int encryptNumBytes = fromClient.readInt();
					byte [] block = new byte[encryptNumBytes];
					fromClient.readFully(block, 0, encryptNumBytes);
					//System.out.println("decrypting block: " + new String(block));
					byte [] decrypt_block = AESKeyUtils.decrypt_bytes(block, session_key);
					//int numBytes = decrypt_block.length;
					//System.out.println("length of block: "+numBytes);

					if (numBytes > 0) {
						times_read++;
						bufferedFileOutputStream.write(decrypt_block, 0, numBytes);
					}

					if (numBytes < 128) {
						System.out.println("File transmission complete.");
						//System.out.println("times read: "+times_read);
						times_read = 0;

//						// there is trailing data for some reason. this clears the trailing data in the socket so it doesn't interfere with the next packet that the client sends.
//						try{
//							byte[] remaining_data = new byte[128];
//							System.out.println("i am here");
//							fromClient.read(remaining_data);
//							System.out.println(remaining_data);
//						}catch(Exception e){
//							e.printStackTrace();
//							continue;
//						}

						if (bufferedFileOutputStream != null) {
							bufferedFileOutputStream.close();
						}
						if (bufferedFileOutputStream != null) {
							fileOutputStream.close();
						}




//						fromClient.close();
//						toClient.close();
//						connectionSocket.close();
					}
				}

			}
		} catch (Exception e) {e.printStackTrace();}

	}

}
