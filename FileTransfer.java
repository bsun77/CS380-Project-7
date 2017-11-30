import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Scanner;
import java.util.zip.CRC32;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class FileTransfer {
	public static void main(String[] args) throws Exception{
		if(args[0].equals("makekeys")){
			keyGen();
		} else if (args[0].equals("server")){
			server(args[1], Integer.parseInt(args[2]));
		} else if (args[0].equals("client")){
			client(args[1], args[2], Integer.parseInt(args[3]));
		}
	}

	public static void keyGen(){
		try {
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
			gen.initialize(4096); // you can use 2048 for faster key generation
			KeyPair keyPair = gen.genKeyPair();
			PrivateKey privateKey = keyPair.getPrivate();
			PublicKey publicKey = keyPair.getPublic();
			try (ObjectOutputStream oos = new ObjectOutputStream(
					new FileOutputStream(new File("public.bin")))) {
				oos.writeObject(publicKey);
			}
			try (ObjectOutputStream oos = new ObjectOutputStream(
					new FileOutputStream(new File("private.bin")))) {
				oos.writeObject(privateKey);
			}
		} catch (NoSuchAlgorithmException | IOException e) {
			e.printStackTrace(System.err);
		}
	}

	public static void server(String privatekey, int port) throws Exception{
		try (ServerSocket serverSocket = new ServerSocket(port)) {
			while(true){
				Socket socket = serverSocket.accept();
				ObjectInputStream is = new ObjectInputStream(socket.getInputStream());			
				ObjectOutputStream os = new ObjectOutputStream(socket.getOutputStream());
				boolean forever = true;
				String filename = "";
				Message msg;
				String file;
				int chunksize;
				long totalsize = 0;
				Cipher aesCipher = null;
				int numchunks = 0;
				int i = 0;
				int whereami = 0;

				byte[] stuff = null;
				while(forever){
					msg = (Message)is.readObject();
					if(msg.getType() == MessageType.DISCONNECT){
						socket.close();
						forever = false;
					} else if (msg.getType() == MessageType.START){
						StartMessage start = (StartMessage) msg;
						file = start.getFile();
						byte[] key = start.getEncryptedKey();
						chunksize = start.getChunkSize();
						totalsize = start.getSize();
						stuff = new byte[(int)totalsize];
						ObjectInputStream ois = new ObjectInputStream(new FileInputStream(new File(privatekey)));
						PrivateKey pkey = (PrivateKey)ois.readObject();
						ois.close();
						Cipher cipher = Cipher.getInstance("RSA");
						cipher.init(Cipher.UNWRAP_MODE, pkey);
						Key trueKey = cipher.unwrap(key, "AES", Cipher.SECRET_KEY);
						aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
						aesCipher.init(Cipher.DECRYPT_MODE, trueKey);
						numchunks = (int) Math.ceil((float)totalsize/chunksize);
						filename = start.getFile();
						Message ack = new AckMessage(0);
						os.writeObject(ack);
					} else if (msg.getType() == MessageType.STOP){
						Message ack = new AckMessage(-1);
						os.writeObject(ack);
					} else if (msg.getType() == MessageType.CHUNK){
						Chunk chunk = (Chunk) msg;
						if(chunk.getSeq()==i){
							byte[] data = aesCipher.doFinal(chunk.getData());
							if(checkCRC(chunk.getCrc(), data)){
//								System.out.println("size " + data.length);
								for(int j = 0; j < data.length && whereami < stuff.length; j++, whereami++){
									stuff[whereami] = data[j];
								}
								System.out.println("Chunk received ["+(i+1)+"/"+numchunks+"].");
							} else {
								System.out.println("incorrect crc.");
							}
							i++;
						}
						Message ack = new AckMessage(i);
						os.writeObject(ack);
					}
				}
				if ( whereami == totalsize){
					System.out.println("Transfer complete.");
					System.out.println(filename);
					FileOutputStream fos = new FileOutputStream(new File("_"+filename));
					fos.write(stuff);
					fos.close();
				}


			}
		}
	}

	public static void client(String publickey, String ipAddress, int port) throws Exception{
		try (Socket socket = new Socket(ipAddress, port)){
			System.out.println("Connected to server: " +ipAddress);			
			ObjectOutputStream os = new ObjectOutputStream(socket.getOutputStream());
			ObjectInputStream is = new ObjectInputStream(socket.getInputStream());
			
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128);
			Key key = keyGen.generateKey();

			ObjectInputStream ois = new ObjectInputStream(new FileInputStream(new File(publickey)));
			PublicKey pubkey = (PublicKey)ois.readObject();
			ois.close();

			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.WRAP_MODE, pubkey);
			byte[] wrapkey = cipher.wrap(key);
			Scanner userinput = new Scanner(System.in);
			System.out.println("Enter path: ");
			String filepath = userinput.nextLine();
			File file = new File(filepath);
			int totalsize = (int) file.length();
			int chunksize = 1024;
			if(file.exists()){
				System.out.println("Enter chunk size [1024]: ");
				chunksize = userinput.nextInt();
				userinput.close();
			}
			int numchunk = (int) Math.ceil((float)totalsize/chunksize);
			Chunk[] totalfile = new Chunk[numchunk];
			FileInputStream fis = new FileInputStream(file);
			Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			aesCipher.init(Cipher.ENCRYPT_MODE, key);
			for(int i = 0; i < totalfile.length; i++){
				byte[] data = new byte[chunksize];
				fis.read(data);
				CRC32 crc32 = new CRC32();
				crc32.update(data);
				int a = (int) crc32.getValue();
				byte[] encrypted = aesCipher.doFinal(data);
				Chunk chunklighttuna = new Chunk(i,encrypted,(int)crc32.getValue());
				totalfile[i] = chunklighttuna;
			}			
			fis.close();
			int seqnumber = 0;
			Message startmsg = new StartMessage(filepath, wrapkey, chunksize);
			os.writeObject(startmsg);
			
			boolean running = true;
			while(running){
				AckMessage ack = (AckMessage) is.readObject();
				if(ack.getSeq()==seqnumber){
					System.out.println("Chunks completed ["+(seqnumber+1)+"/"+numchunk+"]");
					os.writeObject(totalfile[seqnumber]);
					seqnumber++;
					if(seqnumber == totalfile.length){
						running = false;
					}
				} else {
					running = false;
				}
			}
			os.writeObject(new DisconnectMessage());
		}
	}

	public static boolean checkCRC(int crc, byte[] data){
		CRC32 crc32 = new CRC32();
		crc32.update(data);
		return crc==(int)crc32.getValue();
	}
}

