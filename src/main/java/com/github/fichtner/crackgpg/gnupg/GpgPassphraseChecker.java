package com.github.fichtner.crackgpg.gnupg;

import java.io.IOException;
import java.io.InputStream;
import java.security.Provider;
import java.security.Security;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;

public class GpgPassphraseChecker implements PassphraseChecker {

	private static final Provider provider = new org.bouncycastle.jce.provider.BouncyCastleProvider();

	static {
		Security.addProvider(provider);
	}

	private final PGPSecretKey pgpSecretKey;

	// private final JcePBESecretKeyDecryptorBuilder decryptorBuilder = new
	// JcePBESecretKeyDecryptorBuilder()
	// .setProvider("BC");

	public GpgPassphraseChecker(InputStream keyInputStream) throws IOException,
			PGPException {
		this.pgpSecretKey = readSecretKey(keyInputStream, null);
	}

	public GpgPassphraseChecker(InputStream keyInputStream, String keyId)
			throws IOException, PGPException {
		this.pgpSecretKey = readSecretKey(keyInputStream, keyId);
	}

	private static PGPSecretKey readSecretKey(InputStream input, String keyId)
			throws IOException, PGPException {
		for (@SuppressWarnings("unchecked")
		Iterator<PGPSecretKeyRing> keyRingIter = new PGPSecretKeyRingCollection(
				PGPUtil.getDecoderStream(input)).getKeyRings(); keyRingIter
				.hasNext();) {
			for (@SuppressWarnings("unchecked")
			Iterator<PGPSecretKey> keyIter = keyRingIter.next().getSecretKeys(); keyIter
					.hasNext();) {
				PGPSecretKey key = keyIter.next();
				String id = bytArrayToHex(key.getPublicKey().getFingerprint());
				if ((keyId == null || keyId.equalsIgnoreCase(id.substring(id
						.length() - 8))) && key.isSigningKey()) {
					return key;
				}
			}
		}
		throw new IllegalArgumentException("No signing key in keyring");
	}

	private static String bytArrayToHex(byte[] a) {
		StringBuilder sb = new StringBuilder();
		for (byte b : a)
			sb.append(String.format("%02x", b & 0xff));
		return sb.toString();
	}

	@SuppressWarnings("deprecation")
	@Override
	public boolean checkPassphrase(char[] pass) {
		try {
			pgpSecretKey.extractPrivateKey(pass, provider);
		} catch (PGPException e) {
			return false;
		}
		return true;
	}

}
