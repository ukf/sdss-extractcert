package uk.ac.sdss.extractcert;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * This class gives access to a set of test client credentials for
 * the UK federation, in the form of a Java KeyStore.
 *
 * @author iay
 */
abstract class TestCredentialKeyStore {

	public static KeyStore getInstance() throws CryptoException {
		try {
			KeyStore ks = KeyStore.getInstance("PKCS12");
			char[] pass = new char[]{'p', 'a', 's', 's'};
			InputStream is = TestCredentialKeyStore.class.getResourceAsStream("ssl_test.p12");
			if (is == null)
				throw new CryptoException("could not access credential resource");
			ks.load(is, pass);
			return ks;
		} catch (IOException e) {
			throw new CryptoException("can't access PKCS#12 credentials", e);
		} catch (KeyStoreException e) {
			throw new CryptoException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException(e);
		} catch (CertificateException e) {
			throw new CryptoException(e);
		}
	}
	
}
