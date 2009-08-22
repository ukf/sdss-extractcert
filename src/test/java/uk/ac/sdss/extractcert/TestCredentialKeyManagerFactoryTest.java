package uk.ac.sdss.extractcert;

import java.security.PrivateKey;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509KeyManager;

import junit.framework.TestCase;

public class TestCredentialKeyManagerFactoryTest extends TestCase {

	public final void testGetInstance() throws Exception {
		KeyManagerFactory kmf = TestCredentialKeyManagerFactory.getInstance();
		assertNotNull(kmf);
		KeyManager[] kms = kmf.getKeyManagers();
		assertEquals(1, kms.length);
		KeyManager km = kms[0];
		assertTrue(km instanceof X509KeyManager);
		X509KeyManager xkm = (X509KeyManager)km;
		
		// check that we can pick an appropriate entry when asked
		String[] clientAliases = xkm.getClientAliases("RSA", null);
		assertEquals(1, clientAliases.length);
		String alias = clientAliases[0];
		assertEquals("tester", alias);
		
		PrivateKey pk = xkm.getPrivateKey(alias);
		assertNotNull(pk);
	}
	
}
