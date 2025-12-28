package ar.emily.chat.stuff;

import module java.base;
import chat.stuffs.proto.Handshake;
import com.google.protobuf.ByteString;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;

import java.security.Signature;

@SuppressWarnings("preview")
public final class ServerMain {

  private static final Logger LOGGER = LoggerUtil.getLogger();

  private static final ScopedValue<ServerInfo> SERVER_INFO = ScopedValue.newInstance();
  private static final SecureRandom RANDOM_SOURCE;

  static {
    try {
      RANDOM_SOURCE = SecureRandom.getInstance("NativePRNGNonBlocking");
    } catch (final NoSuchAlgorithmException ex) {
      final var initEx = new ExceptionInInitializerError("use linux");
      initEx.initCause(ex);
      throw initEx;
    }
  }

  private static final short MAGIC_NUMBER = (short) 0xea68;
  private static final short PROTOCOL_VERSION = 0;

  private static @Nullable String findArgValue(final String[] args, final String key) {
    for (int i = 0; i < args.length; ++i) {
      final String arg = args[i];
      if (arg.regionMatches(true, 2, key, 0, key.length())) {
        final int eqIdx = arg.indexOf('=');
        if (eqIdx != -1) {
          return arg.substring(eqIdx + 1);
        } else if (i == args.length - 1) {
          return null;
        } else {
          return args[i + 1];
        }
      }
    }

    return null;
  }

  private static char @Nullable [] findOrRequestKeyStorePassword(final String[] args) {
    // launch argument overrides system property overrides environment variable
    // if none of those are found, request from standard input
    return Optional.ofNullable(findArgValue(args, "keystore-password"))
        .or(() -> Optional.ofNullable(System.getProperty("chat.stuff.keystore.password")))
        .or(() -> Optional.ofNullable(System.getenv("CHAT_STUFF_KEYSTORE_PASSWORD")))
        .map(String::toCharArray)
        .or(() ->
            Optional.ofNullable(System.console())
                .map(console -> console.readPassword("Enter keystore password..."))
        ).orElse(null);
  }

  private static Path findKeyStorePath(final String[] args) {
    // launch argument overrides system property overrides environment variable
    // if none of those are found, default to cwd/keystore
    return Optional.ofNullable(findArgValue(args, "keystore-location"))
        .or(() -> Optional.ofNullable(System.getProperty("chat.stuff.keystore.location")))
        .or(() -> Optional.ofNullable(System.getenv("CHAT_STUFF_KEYSTORE_LOCATION")))
        .map(Path::of)
        .orElse(Path.of("keystore"));
  }

  private KeyPair loadSigningKeyPair(final Path keyStorePath, final String[] args) throws IOException {
    if (true) { return CryptoUtil.signatureKeyPairGenerator(new SecureRandom()).generateKeyPair(); }

    if (Files.notExists(keyStorePath)) {
      LOGGER.warn("Keystore file does not exist, generating brand new signing keypair and saving it");
      final char[] keyStorePassword = findOrRequestKeyStorePassword(args);
      if (keyStorePassword == null) {
        LOGGER.error("No keystore password specified, server will now shut down");
        System.exit(2);
        throw new RuntimeException(); // never reached
      }

      final KeyPair signingKeyPair = CryptoUtil.signatureKeyPairGenerator(null).generateKeyPair();
      try (final var out = Files.newOutputStream(keyStorePath)) {
        return signingKeyPair;
      } finally {
        Arrays.fill(keyStorePassword, '\0');
      }
    }

    final char[] keyStorePassword = findOrRequestKeyStorePassword(args);
    if (keyStorePassword == null) {
      LOGGER.error("No keystore password specified, server will now shut down");
      System.exit(1);
      throw new RuntimeException(); // never reached
    }

    try {
      return null;
    } finally {
      Arrays.fill(keyStorePassword, '\0');
    }
  }

  void main(final String[] args) throws InterruptedException, IOException {
    final KeyPair signingKeyPair = loadSigningKeyPair(findKeyStorePath(args), args);
    LOGGER.info("Public signing key: {}", HexFormat.of().formatHex(signingKeyPair.getPublic().getEncoded()));

    try (final var scope = StructuredTaskScope.open()) {
      try (final var serverChannel = ServerSocketChannel.open()) {
        ScopedValue.where(
            SERVER_INFO,
            new ServerInfo(serverChannel, signingKeyPair.getPublic(), signingKeyPair.getPrivate())
        ).run(() -> scope.fork(this::serverAcceptLoop));

        new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))
            .lines().anyMatch(Predicate.isEqual("shutdown").or(Objects::isNull));
      } catch (final IOException ex) {
        try {
          scope.join();
        } catch (final InterruptedException intEx) {
          ex.addSuppressed(intEx);
        }

        throw ex;
      }

      scope.join();
    }
  }

  private void serverAcceptLoop() {
    final ServerInfo serverInfo = SERVER_INFO.get();
    try (final var scope = StructuredTaskScope.open(StructuredTaskScope.Joiner.awaitAll())) {
      try {
        while (true) {
          final SocketChannel client = serverInfo.ch.accept();
          scope.fork(() -> {
            SocketAddress remoteAddress = null;
            try (client) {
              remoteAddress = client.getRemoteAddress();
              handleClient(client);
            } catch (final Exception ex) {
              synchronized (System.err) {
                System.err.printf("Unexpected error handling client %s%n", remoteAddress);
                ex.printStackTrace(System.err);
              }
            }
          });
        }
      } catch (final ClosedByInterruptException _) {
      } catch (final AsynchronousCloseException _) {
        try {
          scope.join();
        } catch (final InterruptedException _) {
          Thread.currentThread().interrupt();
        }
      } catch (final IOException ex) {
        try {
          scope.join();
        } catch (final InterruptedException _) {
          Thread.currentThread().interrupt();
        }

        throw new UncheckedIOException(ex);
      }
    }
  }

  private void handleClient(final SocketChannel ch) throws IOException {
    final ByteBuffer stupidBuffer = ByteBuffer.allocateDirect(Short.BYTES);
    final short magicNumber = NetUtil.readNBytes(ch, stupidBuffer).getShort();
    if (magicNumber != MAGIC_NUMBER) {
      return;
    }

    final InputStream in = Channels.newInputStream(ch);
    final OutputStream out = Channels.newOutputStream(ch);
    final short version = NetUtil.readNBytes(ch, stupidBuffer).getShort();
    if (version != PROTOCOL_VERSION) {
      Handshake.AcceptStatus.newBuilder()
          .setDenyReason(
              String.format("Incompatible protocol version (expected %d, got %d)", PROTOCOL_VERSION, version)
          ).build()
          .writeDelimitedTo(out);
      return;
    }

    Handshake.AcceptStatus.getDefaultInstance().writeDelimitedTo(out);

    final Signature signer = CryptoUtil.signer();

    final KeyFactory keyXchgKeyFactory = CryptoUtil.keyXchgKeyFactory();
    final KeyPair keyXchgKeyPair = CryptoUtil.keyXchgKeyPairGenerator().generateKeyPair();
    final byte[] publicKey =
        CryptoUtil.encodePublicKey(keyXchgKeyFactory, keyXchgKeyPair.getPublic());
    final byte[] publicKeySignature =
        CryptoUtil.sign(signer, SERVER_INFO.get().signingPrivateKey(), RANDOM_SOURCE, ByteBuffer.wrap(publicKey));
    final byte[] nonce = new byte[16];
    RANDOM_SOURCE.nextBytes(nonce);
    final byte[] nonceSignature =
        CryptoUtil.sign(signer, SERVER_INFO.get().signingPrivateKey(), RANDOM_SOURCE, ByteBuffer.wrap(nonce));

    final Handshake.Hello clientHello = Handshake.Hello.parseDelimitedFrom(in);
    final PublicKey clientPublicKey;
    try {
      clientPublicKey = CryptoUtil.decodePublicKey(keyXchgKeyFactory, clientHello.getKeyXchgPublicKey().toByteArray());
    } catch (final InvalidKeySpecException ex) {
      throw new IOException(ex);
    }

    Handshake.Hello.newBuilder()
        .setKeyXchgPublicKey(ByteString.copyFrom(publicKey))
        .setKeyXchgPublicKeySignature(ByteString.copyFrom(publicKeySignature))
        .setNonce(ByteString.copyFrom(nonce))
        .setNonceSignature(ByteString.copyFrom(nonceSignature))
        .build()
        .writeDelimitedTo(out);

    final MessageDigest handshakeMessageDigest = CryptoUtil.handshakeMessageDigest();
    handshakeMessageDigest.update(clientHello.getKeyXchgPublicKey().asReadOnlyByteBuffer());
    handshakeMessageDigest.update(clientHello.getKeyXchgPublicKeySignature().asReadOnlyByteBuffer());
    handshakeMessageDigest.update(clientHello.getNonce().asReadOnlyByteBuffer());
    handshakeMessageDigest.update(clientHello.getNonceSignature().asReadOnlyByteBuffer());
    handshakeMessageDigest.update(publicKey);
    handshakeMessageDigest.update(publicKeySignature);
    handshakeMessageDigest.update(nonce);
    final byte[] handshakeHash = handshakeMessageDigest.digest(nonceSignature);

    final Keys keys =
        CryptoUtil.generateKeys(
            keyXchgKeyPair.getPrivate(),
            RANDOM_SOURCE,
            clientPublicKey,
            handshakeHash,
            nonce,
            clientHello.getNonce().toByteArray()
        );

    final Cipher decryptCipher = CryptoUtil.cipher(Cipher.DECRYPT_MODE, keys.localKey(), keys.localIv(), RANDOM_SOURCE);
    final Cipher encryptCipher =
        CryptoUtil.cipher(Cipher.ENCRYPT_MODE, keys.remoteKey(), keys.remoteIv(), RANDOM_SOURCE);

    final InputStream cipherIn = new CipherInputStream(in, decryptCipher);
    final OutputStream cipherOut = new CipherOutputStream(out, encryptCipher);

    // uhhhh message loop
  }

  private record ServerInfo(ServerSocketChannel ch, PublicKey signingPublicKey, PrivateKey signingPrivateKey) {
  }
}
