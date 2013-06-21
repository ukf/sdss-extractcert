/*
 * Copyright (C) 2013 University of Edinburgh.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package uk.ac.sdss.extractcert;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

import javax.net.ssl.KeyManagerFactory;

/**
 * This class gives access to a set of test client credentials for
 * the UK federation, in the form of an initialised Java KeyManagerFactory.
 *
 * @author iay
 */
public abstract class TestCredentialKeyManagerFactory {

	public static KeyManagerFactory getInstance() throws CryptoException {
		KeyManagerFactory kmf;
		try {
			kmf = KeyManagerFactory.getInstance("SunX509");
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException("can't get X.509 key manager factory instance", e);
		}
		char[] pass = new char[]{'p', 'a', 's', 's'};
		try {
			kmf.init(TestCredentialKeyStore.getInstance(), pass);
		} catch (KeyStoreException e) {
			throw new CryptoException("can't initialise key manager factory instance", e);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException("can't initialise key manager factory instance", e);
		} catch (UnrecoverableKeyException e) {
			throw new CryptoException("can't initialise key manager factory instance", e);
		}
		return kmf;
	}
	
}
