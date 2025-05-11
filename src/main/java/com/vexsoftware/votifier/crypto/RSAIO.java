package com.vexsoftware.votifier.crypto;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Static utility methods for saving and loading RSA key pairs.
 *
 * @author Blake Beaupain, mzcy_ (Recode, don't use javax classes)
 */
public class RSAIO {

	/**
	 * Saves the key pair to the disk.
	 *
	 * @param directory The directory to save to
	 * @param keyPair   The key pair to save
	 * @throws Exception If an error occurs
	 */
	public static void save(File directory, KeyPair keyPair) throws Exception {
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();

		// Store the public key.
		X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKey.getEncoded());
		try (FileOutputStream out = new FileOutputStream(new File(directory, "public.key"))) {
			out.write(Base64.getEncoder().encode(publicSpec.getEncoded()));
		}

		// Store the private key.
		PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
		try (FileOutputStream out = new FileOutputStream(new File(directory, "private.key"))) {
			out.write(Base64.getEncoder().encode(privateSpec.getEncoded()));
		}
	}

	/**
	 * Loads an RSA key pair from a directory. The directory must have the files
	 * "public.key" and "private.key".
	 *
	 * @param directory The directory to load from
	 * @return The key pair
	 * @throws Exception If an error occurs
	 */
	public static KeyPair load(File directory) throws Exception {
		// Read the public key file.
		File publicKeyFile = new File(directory, "public.key");
		byte[] encodedPublicKey;
		try (FileInputStream in = new FileInputStream(publicKeyFile)) {
			ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			int nRead;
			byte[] data = new byte[16384];
			while ((nRead = in.read(data, 0, data.length)) != -1) {
			    buffer.write(data, 0, nRead);
			}
			encodedPublicKey = buffer.toByteArray();
		}
		byte[] decodedPublicKey = Base64.getDecoder().decode(encodedPublicKey);

		// Read the private key file.
		File privateKeyFile = new File(directory, "private.key");
		byte[] encodedPrivateKey;
		try (FileInputStream in = new FileInputStream(privateKeyFile)) {
		    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		    int nRead;
		    byte[] data = new byte[16384];
		    while ((nRead = in.read(data, 0, data.length)) != -1) {
		        buffer.write(data, 0, nRead);
		    }
		    encodedPrivateKey = buffer.toByteArray();
		}
		byte[] decodedPrivateKey = Base64.getDecoder().decode(encodedPrivateKey);

		// Instantiate and return the key pair.
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decodedPublicKey);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(decodedPrivateKey);
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
		return new KeyPair(publicKey, privateKey);
	}
}