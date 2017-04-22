package be.nabu.libs.http.jwt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.Key;
import java.text.ParseException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import be.nabu.libs.http.jwt.enums.JWTAlgorithm;
import be.nabu.libs.http.jwt.enums.JWTType;
import be.nabu.libs.types.TypeUtils;
import be.nabu.libs.types.api.ComplexContent;
import be.nabu.libs.types.api.ComplexType;
import be.nabu.libs.types.binding.api.Window;
import be.nabu.libs.types.binding.json.JSONBinding;
import be.nabu.libs.types.java.BeanInstance;
import be.nabu.libs.types.java.BeanResolver;
import be.nabu.utils.codec.TranscoderUtils;
import be.nabu.utils.codec.impl.Base64Decoder;
import be.nabu.utils.codec.impl.Base64Encoder;
import be.nabu.utils.io.IOUtils;

public class JWTUtils {
	
	public static JWTBody decode(Key key, String content) throws ParseException {
		String[] parts = content.split("\\.");
		if (parts.length != 3) {
			throw new ParseException("Expecting three parts in the token: " + content, 0);
		}
		
		try {
			// decode the header
			JWTHeader header = TypeUtils.getAsBean(
				unmarshal((ComplexType) BeanResolver.getInstance().resolve(JWTHeader.class), parts[0].getBytes("ASCII")),
				JWTHeader.class);
			
			// if we have a key, validate it
			if (key != null) {
				if (!header.getAlg().validate(key, parts[0] + "." + parts[1], parts[2])) {
					throw new ParseException("Invalid signature", 1);
				}
			}
			
			return TypeUtils.getAsBean(
				unmarshal((ComplexType) BeanResolver.getInstance().resolve(JWTBody.class), parts[1].getBytes("ASCII")),
				JWTBody.class);
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
	public static String encode(Key key, JWTBody body, JWTAlgorithm algorithm) {
		JWTHeader header = new JWTHeader();
		header.setAlg(algorithm);
		header.setTyp(JWTType.JWT);
		
		try {
			String headerContent = new String(marshal(new BeanInstance<JWTHeader>(header)), "ASCII");
			String bodyContent = new String(marshal(new BeanInstance<JWTBody>(body)), "ASCII");
			
			String signature = algorithm.sign(key, headerContent + "." + bodyContent);
			
			return headerContent + "." + bodyContent + "." + signature;
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
	public static byte[] base64Encode(byte [] content) throws IOException {
		Base64Encoder transcoder = new Base64Encoder();
		transcoder.setBytesPerLine(0);
		return IOUtils.toBytes(TranscoderUtils.transcodeBytes(IOUtils.wrap(content, true), transcoder));
	}
	
	public static byte[] base64Decode(byte [] content) throws IOException {
		return IOUtils.toBytes(TranscoderUtils.transcodeBytes(IOUtils.wrap(content, true), new Base64Decoder()));
	}
	
	private static byte[] marshal(ComplexContent content) throws IOException {
		JSONBinding binding = new JSONBinding(content.getType(), Charset.forName("UTF-8"));
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		binding.marshal(output, content);
		return base64Encode(output.toByteArray());
	}
	
	private static ComplexContent unmarshal(ComplexType type, byte [] content) throws IOException, ParseException {
		JSONBinding binding = new JSONBinding(type, Charset.forName("UTF-8"));
		return binding.unmarshal(new ByteArrayInputStream(base64Decode(content)), new Window[0]);
	}
	
	public static String encrypt(byte [] content, SecretKey key) {
		try {
			Cipher cipher = Cipher.getInstance(key.getAlgorithm());
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] encrypted = cipher.doFinal(content);
			return new String(base64Encode(encrypted), "ASCII");
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	public static byte[] decrypt(String content, SecretKey key) {
		try {
			Cipher cipher = Cipher.getInstance(key.getAlgorithm());
			cipher.init(Cipher.DECRYPT_MODE, key);
			return cipher.doFinal(base64Decode(content.getBytes("ASCII")));
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
