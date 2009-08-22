package uk.ac.sdss.extractcert;

import java.security.KeyStore;
import java.util.Enumeration;

import junit.framework.TestCase;

public class TestCredentialKeyStoreTest extends TestCase {
	
	public final void testGetInstance() throws Exception {
		KeyStore ks = TestCredentialKeyStore.getInstance();
		assertNotNull(ks);
		
		// only one entry
		assertEquals(1, ks.size());
		
		// Extract aliase for that only entry
		Enumeration<String> ens = ks.aliases();
		assertTrue(ens.hasMoreElements());
		String alias = ens.nextElement();
		assertFalse(ens.hasMoreElements());
		assertEquals("tester", alias);
		
		// Acquire that entry
		KeyStore.ProtectionParameter pass =
			new KeyStore.PasswordProtection(new char[]{'p','a','s','s'});
		KeyStore.Entry entry = ks.getEntry(alias, pass);
		assertNotNull(entry);
	}

}
