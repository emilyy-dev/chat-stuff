package ar.emily.chat.stuff;

import javax.crypto.Cipher;
import javax.crypto.KDF;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;

public final class CryptoUtil {

  static final String SIGNATURE_KEY_ALGO = "RSA";
  private static final String KEY_EXCHANGE_ALGO = "X25519";
  private static final String CIPHER_TRANS = "AES/CFB8/NoPadding";
  private static final String SIGNER_ALGO = "SHA3-512withRSA";
  private static final String KEY_AGREEMENT_ALGO = KEY_EXCHANGE_ALGO;
  private static final String KEY_DERIVATION_FUNCTION_ALGO = "HKDF-SHA512";
  private static final String HANDSHAKE_HASH_ALGO = "SHA3-512";
  private static final String KEY_FACTORY_ALGO = KEY_EXCHANGE_ALGO;
  private static final int SIGNING_KEY_SIZE = 4096;
  private static final int CIPHER_BLOCK_SIZE = 16;
  private static final int CIPHER_KEY_SIZE = 32;

  public static KeyPairGenerator signatureKeyPairGenerator(final SecureRandom randomSource) {
    try {
      final KeyPairGenerator generator = KeyPairGenerator.getInstance(SIGNATURE_KEY_ALGO);
      generator.initialize(SIGNING_KEY_SIZE, randomSource);
      return generator;
    } catch (final NoSuchAlgorithmException ex) {
      throw new RuntimeException(ex);
    }
  }

  public static KeyPairGenerator keyXchgKeyPairGenerator() {
    try {
      return KeyPairGenerator.getInstance(KEY_EXCHANGE_ALGO);
    } catch (final NoSuchAlgorithmException ex) {
      throw new RuntimeException(ex);
    }
  }

  public static MessageDigest handshakeMessageDigest() {
    try {
      return MessageDigest.getInstance(HANDSHAKE_HASH_ALGO);
    } catch (final NoSuchAlgorithmException ex) {
      throw new RuntimeException(ex);
    }
  }

  public static KeyFactory keyXchgKeyFactory() {
    try {
      return KeyFactory.getInstance(KEY_FACTORY_ALGO);
    } catch (final NoSuchAlgorithmException ex) {
      throw new RuntimeException(ex);
    }
  }

  public static KeyFactory signingKeyFactory() {
    try {
      return KeyFactory.getInstance(SIGNATURE_KEY_ALGO);
    } catch (final NoSuchAlgorithmException ex) {
      throw new RuntimeException(ex);
    }
  }

  public static Cipher
  cipher(final int mode, final SecretKey key, final byte[] iv, final SecureRandom randomSource) {
    try {
      final Cipher cipher = Cipher.getInstance(CIPHER_TRANS);
      cipher.init(mode, key, new IvParameterSpec(iv), randomSource);
      return cipher;
    } catch (
        final NoSuchAlgorithmException
              | NoSuchPaddingException
              | InvalidKeyException
              | InvalidAlgorithmParameterException ex
    ) {
      throw new RuntimeException(ex);
    }
  }

  public static Signature signer() {
    try {
      return Signature.getInstance(SIGNER_ALGO);
    } catch (final NoSuchAlgorithmException ex) {
      throw new RuntimeException(ex);
    }
  }

  public static byte[] encodePublicKey(final KeyFactory factory, final PublicKey key) {
    try {
      return factory.getKeySpec(key, X509EncodedKeySpec.class).getEncoded();
    } catch (final InvalidKeySpecException ex) {
      throw new RuntimeException(ex);
    }
  }

  public static PublicKey decodePublicKey(final KeyFactory factory, final byte[] encodedKey)
      throws InvalidKeySpecException {
    return factory.generatePublic(new X509EncodedKeySpec(encodedKey));
  }

  public static Keys generateKeys(
      final PrivateKey privateKey,
      final SecureRandom randomSource,
      final PublicKey publicKey,
      final byte[] handshakeHash,
      final byte[] localNonce,
      final byte[] remoteNonce
  ) {
    try {
      final KeyAgreement keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGO);
      keyAgreement.init(privateKey, randomSource);
      keyAgreement.doPhase(publicKey, true);
      final KDF kdf = KDF.getInstance(KEY_DERIVATION_FUNCTION_ALGO);
      final byte[] sharedSecret = keyAgreement.generateSecret();
      final HKDFParameterSpec.Builder keyBuilder =
          HKDFParameterSpec.ofExtract()
              .addSalt(handshakeHash)
              .addIKM(sharedSecret);
      Arrays.fill(sharedSecret, (byte) 0);

      final String localAsHex = HexFormat.of().formatHex(localNonce);
      final byte[] localKeyInfo = String.format("%s key", localAsHex).getBytes(StandardCharsets.UTF_8);
      final byte[] localIvInfo = String.format("%s iv", localAsHex).getBytes(StandardCharsets.UTF_8);
      final SecretKey localKey = kdf.deriveKey("AES", keyBuilder.thenExpand(localKeyInfo, CIPHER_KEY_SIZE));
      final byte[] localIv = kdf.deriveData(keyBuilder.thenExpand(localIvInfo, CIPHER_BLOCK_SIZE));

      final String remoteAsHex = HexFormat.of().formatHex(remoteNonce);
      final byte[] remoteKeyInfo = String.format("%s key", remoteAsHex).getBytes(StandardCharsets.UTF_8);
      final byte[] remoteIvInfo = String.format("%s iv", remoteAsHex).getBytes(StandardCharsets.UTF_8);
      final SecretKey remoteKey = kdf.deriveKey("AES", keyBuilder.thenExpand(remoteKeyInfo, CIPHER_KEY_SIZE));
      final byte[] remoteIv = kdf.deriveData(keyBuilder.thenExpand(remoteIvInfo, CIPHER_BLOCK_SIZE));

      return new Keys(localKey, localIv, remoteKey, remoteIv);
    } catch (final InvalidKeyException | NoSuchAlgorithmException | InvalidAlgorithmParameterException ex) {
      throw new RuntimeException(ex);
    }
  }

  public static byte[]
  sign(final Signature signer, final PrivateKey key, final SecureRandom randomSource, final ByteBuffer payload) {
    try {
      signer.initSign(key, randomSource);
      signer.update(payload);
      return signer.sign();
    } catch (final InvalidKeyException | SignatureException ex) {
      throw new RuntimeException(ex);
    }
  }

  public static boolean
  verify(final Signature signer, final PublicKey key, final ByteBuffer payload, final ByteBuffer signature)
      throws InvalidKeyException, SignatureException {
    signer.initVerify(key);
    signer.update(payload);

    final byte[] bs;
    final int offset;
    final int length;
    if (signature.hasArray()) {
      bs = signature.array();
      offset = signature.arrayOffset() + signature.position();
      length = signature.remaining();
      signature.position(signature.limit());
    } else {
      offset = 0;
      length = signature.remaining();
      bs = new byte[length];
      signature.get(bs);
    }

    return signer.verify(bs, offset, length);
  }

  private CryptoUtil() {
  }
}
