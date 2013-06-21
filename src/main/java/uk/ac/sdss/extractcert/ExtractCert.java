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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

public class ExtractCert {
	
	private static void croak(String s) {
		System.err.println("Fatal error: " + s);
		System.exit(1);
	}

	/**
	 * @param args
	 * @throws CryptoException 
	 * @throws CertificateEncodingException 
	 * @throws IOException 
	 */
	public static void main(String[] args) throws CryptoException, CertificateEncodingException, IOException {
		/*
		 * Parse command-line arguments.
		 */
		if (args.length != 3) {
			System.err.println("Usage: CertExtractor host port outfile");
			System.exit(1);
		}
		String hostName = args[0];
		int portNumber = Integer.parseInt(args[1]);
		String outFileName = args[2];
		File outFile = new File(outFileName);
		
		CertExtractor ce = CertExtractor.getInstance();
		Certificate cert;
		try {
			cert = ce.extractCertificate(hostName, portNumber);
		} catch (CryptoException e) {
			croak(hostName + ":" + portNumber + ": " + e.getMessage());
			return;
		}
		if (cert instanceof X509Certificate) {
			X509Certificate xcert = (X509Certificate)cert;
			// System.out.println("Subject: " + xcert.getSubjectDN());
			// System.out.println("Issuer:  " + xcert.getIssuerDN());
			byte[] certBytes = xcert.getEncoded();
			// System.out.println("encoded len:" + certBytes.length);
			OutputStream fos = new FileOutputStream(outFile);
			fos.write(certBytes);
			fos.close();
		} else {
			croak("certificate not X.509!");
		}
	}

}
