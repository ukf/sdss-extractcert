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
