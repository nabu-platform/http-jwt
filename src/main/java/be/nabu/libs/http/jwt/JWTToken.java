package be.nabu.libs.http.jwt;

import java.security.Principal;
import java.util.Date;
import java.util.List;

import javax.xml.bind.annotation.XmlTransient;

import be.nabu.libs.authentication.api.Token;

public class JWTToken implements Token {
	private JWTBody body;
	
	private static final long serialVersionUID = 1L;
	
	public JWTToken(JWTBody body) {
		this.body = body;
	}
	
	@Override
	public String getRealm() {
		return body.getRlm();
	}
	
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
}