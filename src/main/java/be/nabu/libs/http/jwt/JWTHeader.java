/*
* Copyright (C) 2017 Alexander Verbruggen
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

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
