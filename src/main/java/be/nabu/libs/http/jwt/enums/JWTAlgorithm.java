package be.nabu.libs.http.jwt.enums;

import java.security.Key;

import be.nabu.libs.http.jwt.api.JWTSigner;
import be.nabu.libs.http.jwt.api.JWTSignerFactory;
import be.nabu.libs.http.jwt.api.JWTValidator;
import be.nabu.libs.http.jwt.api.JWTValidatorFactory;

public enum JWTAlgorithm implements JWTSigner, JWTValidator {
	HS256(JWTMacAlgorithm.HS256, JWTMacAlgorithm.HS256),
	HS384(JWTMacAlgorithm.HS384, JWTMacAlgorithm.HS384),
	HS512(JWTMacAlgorithm.HS512, JWTMacAlgorithm.HS512),
	
	RS256(JWTRSAAlgorithm.RS256, JWTRSAAlgorithm.RS256),
	RS384(JWTRSAAlgorithm.RS384, JWTRSAAlgorithm.RS384),
	RS512(JWTRSAAlgorithm.RS512, JWTRSAAlgorithm.RS512),
	PS256(JWTRSAAlgorithm.PS256, JWTRSAAlgorithm.PS256),
	PS384(JWTRSAAlgorithm.PS384, JWTRSAAlgorithm.PS384),
	PS512(JWTRSAAlgorithm.PS512, JWTRSAAlgorithm.PS512)
	;
	
	private JWTValidatorFactory validatorFactory;
	private JWTSignerFactory signerFactory;

	private JWTAlgorithm(JWTSignerFactory signerFactory, JWTValidatorFactory validatorFactory) {
		this.signerFactory = signerFactory;
		this.validatorFactory = validatorFactory;
	}

	public boolean validate(Key key, String signedContent, String signature) {
		return validatorFactory.newValidator().validate(key, signedContent, signature);
	}

	@Override
	public String sign(Key key, String content) {
		return signerFactory.newSigner().sign(key, content);
	}

}
