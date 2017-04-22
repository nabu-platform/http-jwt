package be.nabu.libs.http.jwt;

public interface JWTHandler {
	public JWTBody decode(String body, String signature);
	public String encode(JWTBody body);
}
