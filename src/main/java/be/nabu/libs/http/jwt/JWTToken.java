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
