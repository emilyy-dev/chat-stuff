package ar.emily.chat.stuff;

import com.google.protobuf.ByteString;
import org.jspecify.annotations.Nullable;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.security.auth.DestroyFailedException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public final class KeyStore {

  private static final String ALGO = "PBEWithHmacSHA512AndAES_256";
  private static final byte[] EMPTY_SALT = new byte[8];
  private static final byte[] EMPTY_IV = new byte[16];
  private static final PBEParameterSpec EMPTY_PARAM_SPEC =
      new PBEParameterSpec(EMPTY_SALT, 0, new IvParameterSpec(EMPTY_IV));

  public static KeyStore empty() {
    return new KeyStore();
  }

  public static KeyStore loadFrom(final InputStream in) throws IOException {
    Objects.requireNonNull(in, "in is null");
    return new KeyStore(KeyStoreEntries.parseFrom(in));
  }

  private final Map<String, byte[]> entries;

  private KeyStore() {
    this.entries = HashMap.newHashMap(1);
  }

  private KeyStore(final KeyStoreEntries entries) {
    this.entries = HashMap.newHashMap(entries.getEntriesCount());
    for (final KeyStoreEntry entry : entries.getEntriesList()) {
      this.entries.put(entry.getName(), entry.getData().toByteArray());
    }
  }

  public @Nullable PublicKey getPublicKey(final String name, final String algorithm, final char @Nullable [] password)
      throws NoSuchAlgorithmException, InvalidKeyException {
    Objects.requireNonNull(name, "name is null");
    Objects.requireNonNull(algorithm, "algorithm is null");
    return switch (this.entries.get(name)) {
      case final byte[] data -> tryUnwrap(data, algorithm, password, Cipher.PUBLIC_KEY);
      case null -> null;
    };
  }

  public @Nullable PrivateKey getPrivateKey(final String name, final String algorithm, final char @Nullable [] password)
      throws NoSuchAlgorithmException, InvalidKeyException {
    Objects.requireNonNull(name, "name is null");
    Objects.requireNonNull(algorithm, "algorithm is null");
    return switch (this.entries.get(name)) {
      case final byte[] data -> tryUnwrap(data, algorithm, password, Cipher.PRIVATE_KEY);
      case null -> null;
    };
  }

  public @Nullable SecretKey getSecretKey(final String name, final String algorithm, final char @Nullable [] password)
      throws NoSuchAlgorithmException, InvalidKeyException {
    Objects.requireNonNull(name, "name is null");
    Objects.requireNonNull(algorithm, "algorithm is null");
    return switch (this.entries.get(name)) {
      case final byte[] data -> tryUnwrap(data, algorithm, password, Cipher.SECRET_KEY);
      case null -> null;
    };
  }

  public void deleteEntry(final String name) {
    this.entries.remove(Objects.requireNonNull(name, "name is null"));
  }

  public void addPublicKey(final String name, final char @Nullable [] password, final PublicKey key)
      throws InvalidKeyException {
    Objects.requireNonNull(name, "name is null");
    Objects.requireNonNull(key, "key is null");
    this.entries.put(name, wrap(key, password));
  }

  public void addPrivateKey(final String name, final char @Nullable [] password, final PrivateKey key)
      throws InvalidKeyException {
    Objects.requireNonNull(name, "name is null");
    Objects.requireNonNull(key, "key is null");
    this.entries.put(name, wrap(key, password));
  }

  public void addSecretKey(final String name, final char @Nullable [] password, final SecretKey key)
      throws InvalidKeyException {
    Objects.requireNonNull(name, "name is null");
    Objects.requireNonNull(key, "key is null");
    this.entries.put(name, wrap(key, password));
  }

  public void storeTo(final OutputStream out) throws IOException {
    Objects.requireNonNull(out, "out is null");
    KeyStoreEntries.newBuilder()
        .addAllEntries(this.entries.entrySet().stream().map(KeyStore::serializeEntry).collect(Collectors.toList()))
        .build()
        .writeTo(out);
  }

  private static KeyStoreEntry serializeEntry(final Map.Entry<String, byte[]> entry) {
    return KeyStoreEntry.newBuilder()
        .setName(entry.getKey())
        .setData(ByteString.copyFrom(entry.getValue()))
        .build();
  }

  @SuppressWarnings("unchecked")
  private <T extends Key> T
  tryUnwrap(final byte[] data, final String algorithm, final char @Nullable [] password, final int keyKind)
      throws NoSuchAlgorithmException, InvalidKeyException {
    final Cipher cipher = createCipher(password, Cipher.UNWRAP_MODE);
    return (T) cipher.unwrap(data, algorithm, keyKind);
  }

  private byte[] wrap(final Key key, final char @Nullable [] password) throws InvalidKeyException {
    try {
      final Cipher cipher = createCipher(password, Cipher.WRAP_MODE);
      return cipher.wrap(key);
    } catch (final IllegalBlockSizeException ex) {
      throw new RuntimeException(ex);
    }
  }

  private static Cipher createCipher(final char @Nullable [] password, final int cipherMode) {
    try {
      final Cipher cipher = Cipher.getInstance(ALGO);
      final PBEKeySpec keySpec = new PBEKeySpec(password);
      try {
        final SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGO);
        final SecretKey entryKey = factory.generateSecret(keySpec);
        try {
          cipher.init(cipherMode, entryKey, EMPTY_PARAM_SPEC);
          return cipher;
        } finally {
          entryKey.destroy();
        }
      } finally {
        keySpec.clearPassword();
      }
    } catch (final GeneralSecurityException | DestroyFailedException ex) {
      throw new RuntimeException(ex);
    }
  }
}
