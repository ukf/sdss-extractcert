package uk.ac.sdss.extractcert;

import java.io.IOException;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;

import javax.net.SocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;

public class CertExtractor {
	
	private SocketFactory sf;
	
	private CertExtractor(SocketFactory sf) {
		this.sf = sf;
	}

	public static CertExtractor getInstance() throws CryptoException {
		/*
		 * Acquire key material.
		 */
		KeyManager[] kms = TestCredentialKeyManagerFactory.getInstance().getKeyManagers();
		
		/*
		 * Construct an SSL context.
		 */
		SSLContext context;
		try {
			context = SSLContext.getInstance("SSL");
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException("could not acquire SSL context", e);
		}
		
		/*
		 * Initialise the SSL context with the key material and
		 * a trust manager that always says "yes".
		 */
		try {
			context.init(
					kms,
					new TrustManager[]{
						new DelegateToApplicationX509TrustManager()
					},
					null);
		} catch (KeyManagementException e) {
			throw new CryptoException("could not initialise SSL context", e);
		}
		
		/*
		 * Build the CertExtractor around that SSL context.
		 */
		return new CertExtractor(context.getSocketFactory());
	}

	public Certificate extractCertificate(String hostName, int portNumber) throws CryptoException {
		SSLSocket s;
		try {
			s = (SSLSocket)sf.createSocket(hostName, portNumber);
			s.startHandshake();
			SSLSession session = s.getSession();
			Certificate[] certs = session.getPeerCertificates();
			if (certs.length == 0) {
				throw new CryptoException("no certificates returned");
			}
			return certs[0];
		} catch (UnknownHostException e) {
			throw new CryptoException("can't extract certificate from unknown host " + hostName, e);
		} catch (IOException e) {
			throw new CryptoException("I/O Exception during certificate extraction: " + e.getMessage(), e);
		}
	}
	
}
