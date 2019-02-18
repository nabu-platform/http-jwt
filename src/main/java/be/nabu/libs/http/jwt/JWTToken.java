package be.nabu.libs.http.jwt;

import java.security.Principal;
import java.util.Date;
import java.util.List;

import javax.xml.bind.annotation.XmlTransient;

import be.nabu.libs.authentication.api.Token;

public class JWTToken implements Token {
	private JWTBody body;
	private String realm;
	
	private static final long serialVersionUID = 1L;
	
	public JWTToken() {
		// auto construct
	}
	
	public JWTToken(JWTBody body) {
		this(body, null);
	}
	
	public JWTToken(JWTBody body, String realm) {
		this.body = body;
		this.realm = realm;
	}
	
	@Override
	public String getRealm() {
		return realm == null ? body.getRlm() : realm;
	}

	@XmlTransient
	@Override
	public String getName() {
		return body.getSub();
	}

	@Override
	@XmlTransient
	public Date getValidUntil() {
		return new Date(1000l * body.getExp());
	}
	
	@XmlTransient
	@Override
	public List<Principal> getCredentials() {
		return null;
	}

	public JWTBody getBody() {
		return body;
	}

	public void setBody(JWTBody body) {
		this.body = body;
	}

	public void setRealm(String realm) {
		this.realm = realm;
	}
	
	// necessary for auto-reconstruct
	public void setName(String name) {
		// do nothing
	}
	public void setCredentials(List<Principal> credentials) {
		// do nothing
	}
	public void setValidUntil(Date date) {
		// do nothing
	}
}
