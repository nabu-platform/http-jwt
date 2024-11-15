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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.crypto.SecretKey;

import be.nabu.libs.http.api.server.Session;
import be.nabu.libs.http.api.server.SessionProvider;

public class JWTSessionProvider implements SessionProvider {

	private SessionProvider original;
	private Map<String, JWTSession> sessions = new HashMap<String, JWTSession>();
	private SecretKey secretKey;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private String tokenKey;
	private long tokenTimeout = 1000l*60*60*24;

	public JWTSessionProvider(String tokenKey, SessionProvider original, SecretKey secretKey) {
		this.tokenKey = tokenKey;
		this.original = original;
		this.secretKey = secretKey;
	}
	
	public JWTSessionProvider(String tokenKey, SessionProvider original, PublicKey publicKey, PrivateKey privateKey) {
		this.tokenKey = tokenKey;
		this.original = original;
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}
	
	@Override
	public Session getSession(String sessionId) {
		JWTSession jwtSession = sessions.get(sessionId);
		if (jwtSession == null) {
			jwtSession = JWTSession.build(this, sessionId);
			if (jwtSession != null) {
				synchronized(sessions) {
					sessions.put(sessionId, jwtSession);
				}
			}
		}
		// if the session has a valid jwt token but it is expired, let's generate a new one
		else if (jwtSession.getBody() != null && jwtSession.getBody().getExp() != null && new Date(jwtSession.getBody().getExp() * 1000).before(new Date())) {
			jwtSession.regenerate();
		}
		return jwtSession;
	}

	@Override
	public Session newSession() {
		JWTSession session = new JWTSession(this, UUID.randomUUID().toString().replace("-", ""), null);
		synchronized(sessions) {
			sessions.put(session.getId(), session);
		}
		return session;
	}

	@Override
	public void prune() {
		// prune the original provider
		original.prune();
		// check all sessions to see if they still exist
		synchronized(sessions) {
			List<JWTSession> sessionsToBeDestroyed = new ArrayList<JWTSession>();
			for (JWTSession session : sessions.values()) {
				// if the original is gone, remove the jwt one as well
				if (original.getSession(session.getOriginal().getId()) == null) {
					sessionsToBeDestroyed.add(session);
				}
			}
			for (JWTSession session : sessionsToBeDestroyed) {
				session.destroy();
			}
		}
	}

	void destroy(String id) {
		synchronized(sessions) {
			sessions.remove(id);
		}
	}

	SessionProvider getOriginal() {
		return original;
	}

	SecretKey getSecretKey() {
		return secretKey;
	}

	PrivateKey getPrivateKey() {
		return privateKey;
	}

	PublicKey getPublicKey() {
		return publicKey;
	}

	String getTokenKey() {
		return tokenKey;
	}

	public long getTokenTimeout() {
		return tokenTimeout;
	}

	public void setTokenTimeout(long tokenTimeout) {
		this.tokenTimeout = tokenTimeout;
	}
	
	void register(String id, JWTSession session) {
		synchronized(sessions) {
			sessions.put(id, session);
		}
	}
}
