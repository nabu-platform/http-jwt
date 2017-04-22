package be.nabu.libs.http.jwt.impl;

import java.security.Key;

import javax.crypto.Mac;

import be.nabu.libs.http.jwt.JWTUtils;
import be.nabu.libs.http.jwt.api.JWTSigner;
import be.nabu.libs.http.jwt.api.JWTValidator;

public class MacSignerValidator implements JWTSigner, JWTValidator {

	private Mac mac;
	
	public MacSignerValidator(Mac mac) {
		this.mac = mac;
	}

	@Override
	public boolean validate(Key key, String signedContent, String signature) {
		return sign(key, signedContent).equals(signature);
	}

	@Override
	public String sign(Key key, String content) {
		try {
			mac.init(key);
			mac.update(content.getBytes("ASCII"));
			return new String(JWTUtils.base64Encode(mac.doFinal()), "ASCII");
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}
