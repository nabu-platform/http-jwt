/*
* Copyright (C) 2017 Alexander Verbruggen
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package be.nabu.libs.http.jwt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.Key;
import java.text.ParseException;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import be.nabu.libs.http.jwt.enums.JWTAlgorithm;
import be.nabu.libs.http.jwt.enums.JWTType;
import be.nabu.libs.types.TypeUtils;
import be.nabu.libs.types.api.ComplexContent;
import be.nabu.libs.types.api.ComplexType;
import be.nabu.libs.types.api.KeyValuePair;
import be.nabu.libs.types.binding.api.Window;
import be.nabu.libs.types.binding.json.JSONBinding;
import be.nabu.libs.types.java.BeanInstance;
import be.nabu.libs.types.java.BeanResolver;
import be.nabu.utils.codec.TranscoderUtils;
import be.nabu.utils.codec.impl.Base64Decoder;
import be.nabu.utils.codec.impl.Base64Encoder;
import be.nabu.utils.io.IOUtils;

public class JWTUtils {
	
	public static JWTBody decode(Map<String, Key> keys, String content) throws ParseException {
		String[] parts = content.split("\\.");
		if (parts.length != 3) {
			throw new ParseException("Expecting three parts in the token: " + content, 0);
		}
		
		try {
			// decode the header
			JWTHeader header = TypeUtils.getAsBean(
				unmarshal((ComplexType) BeanResolver.getInstance().resolve(JWTHeader.class), parts[0].getBytes("ASCII")),
				JWTHeader.class);
			if (header.getValues() == null) {
				throw new IllegalArgumentException("Could not determine key id from jwt header");
			}
			String keyId = null;
			for (KeyValuePair pair : header.getValues()) {
				if ("kid".equals(pair.getKey())) {
					keyId = pair.getValue();
				}
			}
			if (keyId == null) {
				throw new IllegalArgumentException("Could not determine key id from jwt header");
			}
			else if (keys.get(keyId) == null) {
				throw new IllegalArgumentException("The provided keys do not contain the requested key id: " + keyId);
			}
			return decode(keys.get(keyId), content);
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
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
			// in rfc 7515 (https://tools.ietf.org/html/rfc7515) they declare that the padding must be removed (even though padding is optional in base64url encoding)
			// they also specify the need for base64url (as opposed to default base64) encoding
			String headerContent = new String(marshal(new BeanInstance<JWTHeader>(header)), "ASCII").replaceAll("[=]+$", "");
			String bodyContent = new String(marshal(new BeanInstance<JWTBody>(body)), "ASCII").replaceAll("[=]+$", "");
			
			String signature = algorithm.sign(key, headerContent + "." + bodyContent).replaceAll("[=]+$", "");
			
			return headerContent + "." + bodyContent + "." + signature;
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
	public static byte[] base64Encode(byte [] content) throws IOException {
		Base64Encoder transcoder = new Base64Encoder();
		transcoder.setUseBase64Url(true);
		transcoder.setBytesPerLine(0);
		return IOUtils.toBytes(TranscoderUtils.transcodeBytes(IOUtils.wrap(content, true), transcoder));
	}
	
	public static byte[] base64Decode(byte [] content) throws IOException {
		Base64Decoder transcoder = new Base64Decoder();
		transcoder.setUseBase64Url(true);
		return IOUtils.toBytes(TranscoderUtils.transcodeBytes(IOUtils.wrap(content, true), transcoder));
	}
	
	private static byte[] marshal(ComplexContent content) throws IOException {
		JSONBinding binding = new JSONBinding(content.getType(), Charset.forName("UTF-8"));
		binding.setExpandKeyValuePairs(true);
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
