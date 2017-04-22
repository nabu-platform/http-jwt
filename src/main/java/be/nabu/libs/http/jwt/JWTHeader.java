package be.nabu.libs.http.jwt;

import java.util.List;

import be.nabu.libs.http.jwt.enums.JWTAlgorithm;
import be.nabu.libs.http.jwt.enums.JWTType;
import be.nabu.libs.types.api.KeyValuePair;

public class JWTHeader {
	// the algorithm used
	private JWTAlgorithm alg;
	
	// the type used
	private JWTType typ;
	
	// any additional fields
	private List<KeyValuePair> values;
	
	public JWTAlgorithm getAlg() {
		return alg;
	}

	public void setAlg(JWTAlgorithm alg) {
		this.alg = alg;
	}

	public JWTType getTyp() {
		return typ;
	}

	public void setTyp(JWTType typ) {
		this.typ = typ;
	}

	public List<KeyValuePair> getValues() {
		return values;
	}

	public void setValues(List<KeyValuePair> values) {
		this.values = values;
	}
}
