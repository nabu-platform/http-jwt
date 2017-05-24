package be.nabu.libs.http.jwt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.nabu.libs.authentication.TokenSerializerFactory;
import be.nabu.libs.authentication.api.Token;
import be.nabu.libs.authentication.api.TokenSerializer;
import be.nabu.libs.http.api.server.Session;
import be.nabu.libs.http.jwt.enums.JWTAlgorithm;

public class JWTSession implements Session {

	private Session original;
	private JWTSessionProvider provider;
	private static Logger logger = LoggerFactory.getLogger(JWTSession.class);
	private List<String> ids = new ArrayList<String>();
	private JWTBody body;
	
	static JWTSession build(JWTSessionProvider provider, String id) {
		if (id.matches(".+\\..+\\..+")) {
			try {
				JWTBody body = JWTUtils.decode(provider.getPublicKey() == null ? provider.getSecretKey() : provider.getPublicKey(), id);
				// if the token is expired, it can no longer be used
				if (body.getExp() == null || new Date(body.getExp() * 1000).before(new Date())) {
					return null;
				}
				return new JWTSession(provider, id, body);
			}
			catch (ParseException e) {
				logger.warn("Invalid jwt token: " + id, e);
			}
		}
		return null;
	}
	
	JWTSession(JWTSessionProvider provider, String id, JWTBody body) {
		this.provider = provider;
		this.body = body;
		this.ids.add(id);
		this.original = provider.getOriginal().newSession();
		
		// if we have a body, we need a secret key to decrypt it
		if (body != null && provider.getTokenKey() != null && body.getBdy() != null && body.getBdt() != null && provider.getSecretKey() != null) {
			TokenSerializer<Token> serializer = TokenSerializerFactory.getInstance().getSerializer(body.getBdt());
			if (serializer == null) {
				throw new IllegalArgumentException("Can not find serializer for type: " + body.getBdt());
			}
			Token deserialize = serializer.deserialize(new ByteArrayInputStream(JWTUtils.decrypt(body.getBdy(), provider.getSecretKey())));
			if (deserialize == null) {
				throw new IllegalArgumentException("Can not recover encrypted token");
			}
			original.set(provider.getTokenKey(), deserialize);
		}
		else if (body != null) {
			original.set(provider.getTokenKey(), new JWTToken(body));
		}
	}
	
	private String generateId(Token token) {
		String id = null;
		if (token != null) {
			body = new JWTBody();
			body.setIat(new Date().getTime() / 1000);
			// be valid at least as long as the token inside it
			Date validUntil = new Date(new Date().getTime() + provider.getTokenTimeout());
			if (token.getValidUntil() != null && token.getValidUntil().after(validUntil)) {
				validUntil = token.getValidUntil();
			}
			body.setExp(validUntil.getTime() / 1000);
			body.setRlm(token.getRealm());
			body.setSub(token.getName());
			TokenSerializer<Token> serializer = TokenSerializerFactory.getInstance().getSerializer(token);
			if (serializer != null) {
				ByteArrayOutputStream output = new ByteArrayOutputStream();
				serializer.serialize(output, token);
				body.setBdt(serializer.getName());
				body.setBdy(JWTUtils.encrypt(output.toByteArray(), provider.getSecretKey()));
			}
			if (provider.getPrivateKey() != null) {
				id = JWTUtils.encode(provider.getPrivateKey(), body, JWTAlgorithm.RS256);	
			}
			else if (provider.getSecretKey() != null) {
				id = JWTUtils.encode(provider.getSecretKey(), body, JWTAlgorithm.HS256);
			}
		}
		if (id == null) {
			id = UUID.randomUUID().toString().replace("-", "");
		}
		return id;
	}
	
	@Override
	public Iterator<String> iterator() {
		return original.iterator();
	}

	@Override
	public String getId() {
		return ids.get(ids.size() - 1);
	}

	@Override
	public Object get(String name) {
		return original.get(name);
	}

	// currently resetting the token reinitiates the id
	void regenerate() {
		this.set(provider.getTokenKey(), original.get(provider.getTokenKey()));
	}
	
	@Override
	public void set(String name, Object value) {
		if (provider.getTokenKey().equals(name)) {
			String newId = generateId((Token) value);
			ids.add(newId);
			provider.register(newId, this);
		}
		original.set(name, value);
	}

	@Override
	public void destroy() {
		for (String id : ids) {
			provider.destroy(id);
		}
		original.destroy();
	}

	Session getOriginal() {
		return original;
	}

	JWTBody getBody() {
		return body;
	}
	
}
