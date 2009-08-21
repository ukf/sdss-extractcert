/**
 * Class representing exceptions for this package.
 */
package uk.ac.sdss.extractcert;

public class CryptoException extends Exception {

	private static final long serialVersionUID = 8870387383893596395L;

	public CryptoException() {
		super();
	}
	
	public CryptoException(String s) {
		super(s);
	}
	
	public CryptoException(Throwable t) {
		super(t);
	}
	
	public CryptoException(String s, Throwable t) {
		super(s, t);
	}

}
