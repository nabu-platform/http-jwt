package be.nabu.libs.http.jwt.enums;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;

import be.nabu.libs.http.jwt.api.JWTSigner;
import be.nabu.libs.http.jwt.api.JWTSignerFactory;
import be.nabu.libs.http.jwt.api.JWTValidator;
import be.nabu.libs.http.jwt.api.JWTValidatorFactory;
import be.nabu.libs.http.jwt.impl.MacSignerValidator;

public enum JWTMacAlgorithm implements JWTSignerFactory, JWTValidatorFactory {
	HS256("HmacSHA256"),
	HS384("HMACSHA384"),
	HS512("HMACSHA512")
	;
	
	private String algorithm;

	private JWTMacAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

	public Mac getMac() {
		try {
			Mac instance = Mac.getInstance(algorithm);
			return instance;
		}
		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public JWTValidator newValidator() {
		return new MacSignerValidator(getMac());
	}

	@Override
	public JWTSigner newSigner() {
		return new MacSignerValidator(getMac());
	}
}
