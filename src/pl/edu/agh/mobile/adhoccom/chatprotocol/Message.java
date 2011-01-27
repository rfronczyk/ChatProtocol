package pl.edu.agh.mobile.adhoccom.chatprotocol;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage;

import com.google.protobuf.ByteString;
import com.google.protobuf.CodedInputStream;
import com.google.protobuf.CodedOutputStream;
import com.google.protobuf.InvalidProtocolBufferException;

public class Message {
	private byte[] body;
	private String sender;
	private int date;
	private String groupName;
	private byte[] groupChalenge;
	private static MessageDigest messageDigest;
	private static final String SECRET = "p28etluthlu0Luh";
	private static PBEParameterSpec paramSpec;
	private static byte[] salt = { 0x7d, 0x60, 0x43, 0x5f, 0x02, (byte) 0xe9, (byte) 0xe0, (byte) 0xae };
	private static SecretKeyFactory keyFactory; 
	
	static {
		try {
			messageDigest = MessageDigest.getInstance("SHA-1");
			keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
			paramSpec = new PBEParameterSpec(salt, 30);
		} catch (NoSuchAlgorithmException e) {
			
		}
	}

	/**
	 * 
	 * @param body
	 * @param sender
	 * @param date Number of <b>seconds</b> from 1970
	 * @param group
	 */
	public Message(byte[] body, String sender, int date, String group) {
		this.body = body;
		this.sender = sender;
		this.date = date;
		this.groupName = group;
	}

	public Message(byte[] body, String sender, int date, String groupName,
			byte[] groupChalenge) {
		this(body, sender, date, groupName);
		this.groupChalenge = groupChalenge;
	}
	
	public String getBody() {
		return new String(body);
	}
	
	public byte[] getBodyBytes() {
		return body;
	}

	public void setBody(String body) {
		this.body = body.getBytes();
	}
	
	public void setBodyBytes(byte[] body) {
		this.body = body;
	}

	public String getSender() {
		return sender;
	}

	public void setSender(String sender) {
		this.sender = sender;
	}

	public int getDate() {
		return date;
	}
	
	public void setDate(int date) {
		this.date = date;
	}
	
	public String getGroupName() {
		return groupName;
	}

	public void setGroupName(String group) {
		this.groupName = group;
	}
	
	@Override
	public String toString() {
		StringBuilder retVal = new StringBuilder();
		retVal.append(sender).append(": ").append(getBody());
		return retVal.toString();
	}

	public byte[] toByteArray() {
		ChatMessage.Builder chatMessage = ChatMessage.newBuilder();
		chatMessage.setBody(ByteString.copyFrom(getBodyBytes()));
		chatMessage.setDate(getDate());
		chatMessage.setSender(getSender());
		chatMessage.setGroupName(getGroupName());
		if (groupChalenge != null) {
			chatMessage.setGroupChalenge(ByteString.copyFrom(groupChalenge));
		}
		
		return chatMessage.build().toByteArray();
	}
	
	public static Message parseFrom(InputStream input) throws ChatMessageException, IOException {
		CodedInputStream stream = CodedInputStream.newInstance(input);
		int size = stream.readRawLittleEndian32();		
		ChatMessage chatMessage = ChatMessage.parseFrom(stream.readRawBytes(size));
		Message msg = new Message(chatMessage.getBody().toByteArray(), chatMessage.getSender(),
				  chatMessage.getDate(), chatMessage.getGroupName(), 
				  chatMessage.getGroupChalenge().toByteArray());
		return msg;
	}
	
	public void writeTo(OutputStream output) throws IOException {
		CodedOutputStream stream = CodedOutputStream.newInstance(output);
		byte[] bytes = toByteArray();
		stream.writeRawLittleEndian32(bytes.length);
		stream.writeRawBytes(bytes);
		stream.flush();
	}

	public static Message parseFrom(DatagramPacket packet) throws ChatMessageException {
		try {
			ChatMessage chatMessage = ChatMessage.parseFrom(packet.getData());
			Message msg = new Message(chatMessage.getBody().toByteArray(), chatMessage.getSender(),
								  chatMessage.getDate(), chatMessage.getGroupName(), 
								  chatMessage.getGroupChalenge().toByteArray());
			return msg;
		} catch(InvalidProtocolBufferException e) {
			throw new ChatMessageException(e.getMessage());
		}
	}

	public void encrypt(String pass) {
		body = encryptBody(body, pass);
		groupChalenge = generateChalenge(groupName, pass);
	}
	
	public void decrypt(String pass) {
		body = decryptBody(body, pass);
	}

	static private synchronized byte[] generateChalenge(String groupName, String pass) {
		if (pass == null || pass.length() == 0) {
			return groupName.getBytes();
		} else {
			messageDigest.reset();
			messageDigest.update(SECRET.getBytes());
			messageDigest.update(groupName.getBytes());
			messageDigest.update(pass.getBytes());
			messageDigest.update(SECRET.getBytes());
			return messageDigest.digest();
		}
	}

	private byte[] encryptBody(byte[] body, String pass) {
		if (pass == null || pass.length() == 0) {
			return body;
		}
		
		byte[] encryptedMessage = null;
		try {
			Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, pass);
			encryptedMessage = cipher.doFinal(body);
		} catch(Exception e) {
		}
		return encryptedMessage;
	}
	
	private byte[] decryptBody(byte[] body, String pass) {
		if (pass == null || pass.length() == 0) {
			return body;
		}
		byte[] decryptedMessage = null;
		try {
			Cipher cipher = getCipher(Cipher.DECRYPT_MODE, pass);
			decryptedMessage = cipher.doFinal(body);
		} catch(Exception e) { 
		}
		return decryptedMessage;
	}

	public boolean canBeDecrypted(String pass) {
		return Arrays.equals(groupChalenge, generateChalenge(this.groupName, pass));
	}
	
	private static Cipher getCipher(int mode, String pass) {
		Cipher cipher = null;
		try {
			PBEKeySpec keySpec = new PBEKeySpec(pass.toCharArray());
			SecretKey key = keyFactory.generateSecret(keySpec);
			cipher = Cipher.getInstance("PBEWithMD5AndDES");
			cipher.init(mode, key, paramSpec);
		} catch(Exception e) {
		}
		
    	return cipher;
	}
}
