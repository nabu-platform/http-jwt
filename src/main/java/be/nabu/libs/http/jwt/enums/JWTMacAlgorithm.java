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

package be.nabu.libs.http.jwt.enums;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;

import be.nabu.libs.http.jwt.api.JWTSigner;
import be.nabu.libs.http.jwt.api.JWTSignerFactory;
import be.nabu.libs.http.jwt.api.JWTValidator;
import be.nabu.libs.http.jwt.api.JWTValidatorFactory;
import be.nabu.libs.http.jwt.impl.MacSignerValidator;

public enum JWTMacAlgorithm implements JWTSignerFactory, JWTValidatorFactory {
	HS256("HmacSHA256"),
	HS384("HMACSHA384"),
	HS512("HMACSHA512")
	;
	
	private String algorithm;

	private JWTMacAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

	public Mac getMac() {
		try {
			Mac instance = Mac.getInstance(algorithm);
			return instance;
		}
		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public JWTValidator newValidator() {
		return new MacSignerValidator(getMac());
	}

	@Override
	public JWTSigner newSigner() {
		return new MacSignerValidator(getMac());
	}
}
