package WithAuthProtocol;

import AuthUtils.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;

public class ServerWithAuthProtocol {

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

		try {
			welcomeSocket = new ServerSocket(port);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());

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
					connectionSocket.close();
				}

				// If the packet is for transferring the filename
				if (packetType == 0) {

					System.out.println("Receiving file...");

					int numBytes = fromClient.readInt();
					byte [] filename = new byte[numBytes];
					// Must use read fully!
					// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
					fromClient.readFully(filename, 0, numBytes);

					fileOutputStream = new FileOutputStream("recv_"+new String(filename, 0, numBytes));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				// If the packet is for transferring a chunk of the file
				} else if (packetType == 1) {

					int numBytes = fromClient.readInt();
					byte [] block = new byte[numBytes];
					fromClient.readFully(block, 0, numBytes);

					if (numBytes > 0)
						bufferedFileOutputStream.write(block, 0, numBytes);

					if (numBytes < 117) {
						System.out.println("Closing connection...");

						if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null) fileOutputStream.close();
						fromClient.close();
						toClient.close();
						connectionSocket.close();
					}
				}

			}
		} catch (Exception e) {e.printStackTrace();}

	}

}
