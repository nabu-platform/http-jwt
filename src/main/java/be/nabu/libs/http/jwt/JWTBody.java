package be.nabu.libs.http.jwt;

import java.util.List;

import be.nabu.libs.types.api.KeyValuePair;

// https://tools.ietf.org/html/draft-jones-json-web-token-07#page-7
public class JWTBody {
	// reserved claims
	
	// expiration time
	private Long exp;
	// not before time
	private Long nbf;
	// issued at time
	private Long iat;
	// issuer
	private String iss;
	// subject
	private String sub;
	// the audience it is intended for
	private String aud;
	// the id of the jwt token
	private String jti;
	
	// private claims
	// realm
	private String rlm;
	// a custom serialized body that it contains
	private String bdy;
	// the body type that it contains which can be used for deserialization
	private String bdt;
	
	// any additional claims
	private List<KeyValuePair> values;

	public Long getExp() {
		return exp;
	}

	public void setExp(Long exp) {
		this.exp = exp;
	}

	public Long getIat() {
		return iat;
	}

	public void setIat(Long iat) {
		this.iat = iat;
	}

	public String getIss() {
		return iss;
	}

	public void setIss(String iss) {
		this.iss = iss;
	}

	public String getSub() {
		return sub;
	}

	public void setSub(String sub) {
		this.sub = sub;
	}

	public String getAud() {
		return aud;
	}

	public void setAud(String aud) {
		this.aud = aud;
	}

	public String getJti() {
		return jti;
	}

	public void setJti(String jti) {
		this.jti = jti;
	}

	public String getRlm() {
		return rlm;
	}

	public void setRlm(String rlm) {
		this.rlm = rlm;
	}
	
	public Long getNbf() {
		return nbf;
	}

	public void setNbf(Long nbf) {
		this.nbf = nbf;
	}

	public String getBdy() {
		return bdy;
	}

	public void setBdy(String bdy) {
		this.bdy = bdy;
	}

	public String getBdt() {
		return bdt;
	}

	public void setBdt(String bdt) {
		this.bdt = bdt;
	}

	public List<KeyValuePair> getValues() {
		return values;
	}

	public void setValues(List<KeyValuePair> values) {
		this.values = values;
	}
}