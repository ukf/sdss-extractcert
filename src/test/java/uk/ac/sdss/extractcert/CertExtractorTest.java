package uk.ac.sdss.extractcert;

import java.security.cert.Certificate;

import junit.framework.TestCase;

public class CertExtractorTest extends TestCase {

	public final void testCertExtractor() throws Exception {
		CertExtractor ce = CertExtractor.getInstance();
		assertNotNull(ce);
		
		// test against a raw Tomcat instance
		Certificate cert = ce.extractCertificate("dlib-idp.edina.ac.uk", 8443);
		assertNotNull(cert);
	}
	
}
