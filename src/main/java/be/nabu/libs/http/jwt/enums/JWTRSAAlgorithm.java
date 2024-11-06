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

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import be.nabu.libs.http.jwt.api.JWTSigner;
import be.nabu.libs.http.jwt.api.JWTSignerFactory;
import be.nabu.libs.http.jwt.api.JWTValidator;
import be.nabu.libs.http.jwt.api.JWTValidatorFactory;
import be.nabu.libs.http.jwt.impl.RsaSignerValidator;

// PS is based on https://bitbucket.org/connect2id/nimbus-jose-jwt/src/b455c3d0fd11fb49971fbe01400bd390f9754e79/src/main/java/com/nimbusds/jose/crypto/RSASSA.java?at=master&fileviewer=file-view-default
public enum JWTRSAAlgorithm implements JWTSignerFactory, JWTValidatorFactory {
	RS256("SHA256withRSA", null),
	RS384("SHA384withRSA", null),
	RS512("SHA512withRSA", null),
	// JWA mandates salt length must equal hash
	PS256("SHA256withRSAandMGF1", new PSSParameterSpec("SHA256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)),
	PS384("SHA384withRSAandMGF1", new PSSParameterSpec("SHA384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1)),
	PS512("SHA512withRSAandMGF1", new PSSParameterSpec("SHA512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1))
	;
	
	private String algorithm;
	private PSSParameterSpec spec;

	private JWTRSAAlgorithm(String algorithm, PSSParameterSpec spec) {
		this.algorithm = algorithm;
		this.spec = spec;
	}
	
	public Signature getSignature() {
		try {
			Signature signature = Signature.getInstance(algorithm);
			if (spec != null) {
				signature.setParameter(spec);
			}
			return signature;
		}
		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		catch (InvalidAlgorithmParameterException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public JWTValidator newValidator() {
		return new RsaSignerValidator(getSignature());
	}

	@Override
	public JWTSigner newSigner() {
		return new RsaSignerValidator(getSignature());
	}
}
