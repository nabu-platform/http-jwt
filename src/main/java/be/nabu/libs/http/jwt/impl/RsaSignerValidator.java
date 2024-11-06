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

package be.nabu.libs.http.jwt.impl;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import be.nabu.libs.http.jwt.JWTUtils;
import be.nabu.libs.http.jwt.api.JWTSigner;
import be.nabu.libs.http.jwt.api.JWTValidator;

public class RsaSignerValidator implements JWTSigner, JWTValidator {

	private Signature signature;

	public RsaSignerValidator(Signature signature) {
		this.signature = signature;
	}
	
	@Override
	public boolean validate(Key key, String signedContent, String signature) {
		try {
			this.signature.initVerify((PublicKey) key);
			this.signature.update(signedContent.getBytes("ASCII"));
			return this.signature.verify(JWTUtils.base64Decode(signature.getBytes("ASCII")));
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public String sign(Key key, String content) {
		try {
			this.signature.initSign((PrivateKey) key);
			this.signature.update(content.getBytes("ASCII"));
			return new String(JWTUtils.base64Encode(this.signature.sign()), "ASCII");
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}
