package be.nabu.libs.http.jwt.api;

import java.security.Key;

public interface JWTValidator {
	public boolean validate(Key key, String signedContent, String signature);
}
