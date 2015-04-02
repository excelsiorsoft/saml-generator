package com.excelsiorsoft.saml;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.util.Base64;

public class CertManager {

	/**
	 * Gets credential used to sign saml assertionts that are produced. This
	 * method assumes the cert and pkcs formatted primary key are on file
	 * system. this data could be stored elsewhere e.g keystore
	 * 
	 * a credential is used to sign saml response, and includes the private key
	 * as well as a cert for the public key
	 * 
	 * @return
	 * @throws Throwable
	 */
	public Credential getSigningCredential(String publicKeyLocation,
			String privateKeyLocation) throws Throwable {
		// create public key (cert) portion of credential
		InputStream inStream = new FileInputStream(publicKeyLocation);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate publicKey = (X509Certificate) cf
				.generateCertificate(inStream);
		inStream.close();

		// create private key
		RandomAccessFile raf = new RandomAccessFile(privateKeyLocation, "r");
		byte[] buf = new byte[(int) raf.length()];

		try {
			raf.readFully(buf);
		} finally {
			raf.close();
		}

		PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(buf);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = kf.generatePrivate(kspec);

		// create credential and initialize
		BasicX509Credential credential = new BasicX509Credential();
		credential.setEntityCertificate(publicKey);
		credential.setPrivateKey(privateKey);

		return credential;
	}

	public X509Certificate getX509Certificate(String publicKeyLocation)
			throws Throwable {

		X509Certificate certificate = null;
		InputStream inStream = null;
		try {
			inStream = new FileInputStream(publicKeyLocation);

			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			certificate = (X509Certificate) cf
					.generateCertificate(inStream);
		} finally {
			inStream.close();
		}
		
		return certificate;
	}
	
	public String getEncodedX509Certificate(String publicKeyLocation) throws Throwable{
		
		return (Base64.encodeBytes(this.getX509Certificate(publicKeyLocation).getEncoded()));
		
	}
}
