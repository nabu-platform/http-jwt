package be.nabu.libs.http.jwt.impl;

import java.security.Key;
import java.text.ParseException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.nabu.libs.authentication.api.Token;
import be.nabu.libs.events.api.EventHandler;
import be.nabu.libs.http.api.HTTPRequest;
import be.nabu.libs.http.api.HTTPResponse;
import be.nabu.libs.http.api.server.AuthenticationHeader;
import be.nabu.libs.http.jwt.JWTBody;
import be.nabu.libs.http.jwt.JWTToken;
import be.nabu.libs.http.jwt.JWTUtils;
import be.nabu.utils.mime.api.Header;
import be.nabu.utils.mime.impl.MimeUtils;

public class JWTBearerHandler implements EventHandler<HTTPRequest, HTTPResponse> {

	private Key key;
	private String realm;
	private Logger logger = LoggerFactory.getLogger(getClass());
	
	public JWTBearerHandler(Key key, String realm) {
		this.key = key;
		this.realm = realm;
	}
	
	@Override
	public HTTPResponse handle(HTTPRequest request) {
		Header header = MimeUtils.getHeader("Authorization", request.getContent().getHeaders());
		if (header != null && header.getValue().substring(0, 6).equalsIgnoreCase("bearer")) {
			String token = header.getValue().substring(7);
			try {
				JWTBody decode = JWTUtils.decode(key, token);
				if (decode != null) {
					request.getContent().setHeader(new SimpleAuthenticationHeader(new JWTToken(decode, realm)));
				}
			}
			catch (ParseException e) {
				logger.debug("Failed to parse token: " + token, e);
			}
		}
		return null;
	}

	public static class SimpleAuthenticationHeader implements AuthenticationHeader {

		private Token token;

		public SimpleAuthenticationHeader(Token token) {
			this.token = token;
		}
		
		@Override
		public String getName() {
			return "X-Remote-User";
		}

		@Override
		public String getValue() {
			return token.getName();
		}

		@Override
		public String[] getComments() {
			return new String[0];
		}
		
		@Override
		public Token getToken() {
			return token;
		}
	}
}
