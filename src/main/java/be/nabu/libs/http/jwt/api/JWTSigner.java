package be.nabu.libs.http.jwt.api;

import java.security.Key;

public interface JWTSigner {
	public String sign(Key key, String content);
}
