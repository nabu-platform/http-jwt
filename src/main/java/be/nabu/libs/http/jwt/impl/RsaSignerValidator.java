package be.nabu.libs.http.jwt.impl;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import be.nabu.libs.http.jwt.JWTUtils;
import be.nabu.libs.http.jwt.api.JWTSigner;
import be.nabu.libs.http.jwt.api.JWTValidator;

public class RsaSignerValidator implements JWTSigner, JWTValidator {

	private Signature signature;

	public RsaSignerValidator(Signature signature) {
		this.signature = signature;
	}
	
	@Override
	public boolean validate(Key key, String signedContent, String signature) {
		try {
			this.signature.initVerify((PublicKey) key);
			this.signature.update(signedContent.getBytes("ASCII"));
			return this.signature.verify(JWTUtils.base64Decode(signature.getBytes("ASCII")));
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public String sign(Key key, String content) {
		try {
			this.signature.initSign((PrivateKey) key);
			this.signature.update(content.getBytes("ASCII"));
			return new String(JWTUtils.base64Encode(this.signature.sign()), "ASCII");
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}
