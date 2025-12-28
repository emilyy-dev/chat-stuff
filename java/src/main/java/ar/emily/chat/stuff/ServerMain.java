package ar.emily.chat.stuff;

import module java.base;
import chat.stuffs.proto.DisconnectOuterClass;
import chat.stuffs.proto.Handshake;
import chat.stuffs.proto.KeepaliveOuterClass;
import chat.stuffs.proto.Messages;
import com.google.protobuf.ByteString;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;

import java.security.Signature;

@SuppressWarnings("preview")
public final class ServerMain {

  private static final Logger LOGGER = LoggerUtil.getLogger();

  private static final Duration READ_WRITE_TIMEOUT = Duration.ofSeconds(10L);
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
    if (Files.notExists(keyStorePath)) {
      LOGGER.warn("Keystore file does not exist, generating brand new signing keypair and saving it");
      final char[] keyStorePassword = findOrRequestKeyStorePassword(args);
      if (keyStorePassword == null) {
        LOGGER.error("No keystore password specified, server will now shut down");
        System.exit(2);
        throw new RuntimeException(); // never reached
      }

      LOGGER.info("Generating new signing keypair...");
      final KeyPair signingKeyPair = CryptoUtil.signatureKeyPairGenerator(RANDOM_SOURCE).generateKeyPair();
      try (final var out = new DataOutputStream(new BufferedOutputStream(Files.newOutputStream(keyStorePath)))) {
        // TODO: password-protect
        final KeyFactory signingKeyFactory = CryptoUtil.signingKeyFactory();
        byte[] bs = CryptoUtil.encodePrivateKey(signingKeyFactory, signingKeyPair.getPrivate());
        out.writeInt(bs.length);
        out.write(bs);
        bs = CryptoUtil.encodePublicKey(signingKeyFactory, signingKeyPair.getPublic());
        out.writeInt(bs.length);
        out.write(bs);
        return signingKeyPair;
      } finally {
        Arrays.fill(keyStorePassword, '\0');
      }
    }

    LOGGER.info("Loading signing keypair from existing keystore...");
    final char[] keyStorePassword = findOrRequestKeyStorePassword(args);
    if (keyStorePassword == null) {
      LOGGER.error("No keystore password specified, server will now shut down");
      System.exit(1);
      throw new RuntimeException(); // never reached
    }

    try (final var in = new DataInputStream(new BufferedInputStream(Files.newInputStream(keyStorePath)))) {
      // TODO: password-protect
      final KeyFactory signingKeyFactory = CryptoUtil.signingKeyFactory();
      byte[] bs = new byte[in.readInt()];
      in.readFully(bs);
      final PrivateKey privateKey = CryptoUtil.decodePrivateKey(signingKeyFactory, bs);

      bs = new byte[in.readInt()];
      in.readFully(bs);
      final PublicKey publicKey = CryptoUtil.decodePublicKey(signingKeyFactory, bs);

      return new KeyPair(publicKey, privateKey);
    } catch (final InvalidKeySpecException ex) {
      throw new RuntimeException(ex);
    } finally {
      Arrays.fill(keyStorePassword, '\0');
    }
  }

  void main(final String[] args) throws InterruptedException, IOException {
    LOGGER.info("Java: {}", Runtime.version());
    final KeyPair signingKeyPair = loadSigningKeyPair(findKeyStorePath(args), args);
    LOGGER.info("Public signing key:\n{}", PEMEncoder.of().encodeToString(signingKeyPair.getPublic()));

    try (final var scope = StructuredTaskScope.open()) {
      try (final var serverChannel = ServerSocketChannel.open()) {
        LOGGER.info("Bound to {}", serverChannel.bind(new InetSocketAddress(39615)).getLocalAddress());
        final ServerInfo serverInfo = new ServerInfo(serverChannel, signingKeyPair.getPublic(), signingKeyPair.getPrivate());
        scope.fork(() -> ScopedValue.where(SERVER_INFO, serverInfo).run(this::serverAcceptLoop));
        new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))
            .lines().anyMatch(Predicate.isEqual("shutdown").or(Objects::isNull));
        LOGGER.info("Shutting down...");
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
        LOGGER.info("Accepting connections");
        while (true) {
          final SocketChannel client = serverInfo.ch.accept();
          scope.fork(() -> acceptClient(client));
        }
      } catch (final ClosedByInterruptException _) {
        LOGGER.info("No new connections will be accepted");
      } catch (final AsynchronousCloseException _) {
        try {
          LOGGER.info("No new connections will be accepted");
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

  private void acceptClient(final SocketChannel client) {
    SocketAddress remoteAddress = null;
    try (client) {
      remoteAddress = client.getRemoteAddress();
      LOGGER.debug("New client from {}", remoteAddress);
      handleClient(client);
      LOGGER.debug("Disconnecting client {}", remoteAddress);
    } catch (final StructuredTaskScope.TimeoutException ex) {
      LOGGER.debug("Read timeout for {}", remoteAddress, ex);
    } catch (final Exception ex) {
      LOGGER.error("Unexpected error handling client {}", remoteAddress, ex);
    }
  }

  private void handleClient(final SocketChannel ch) throws IOException {
    final ByteBuffer stupidBuffer = ByteBuffer.allocateDirect(Short.BYTES);
    final short magicNumber = NetUtil.readNBytes(ch, READ_WRITE_TIMEOUT, stupidBuffer).getShort();
    if (magicNumber != MAGIC_NUMBER) {
      return;
    }

    final InputStream in = new UglyTimeoutSocketChannelInputStream(ch, READ_WRITE_TIMEOUT);
    final OutputStream out = new UglyTimeoutSocketChannelOutputStream(ch, READ_WRITE_TIMEOUT);
    final short version = NetUtil.readNBytes(ch, READ_WRITE_TIMEOUT, stupidBuffer).getShort();
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
    while (true) {
      if (readRequestMessage(cipherIn, cipherOut)) {
        break;
      }
    }
  }

  private boolean readRequestMessage(final InputStream in, final OutputStream out) throws IOException {
    final Messages.Request request = Messages.Request.parseDelimitedFrom(in);
    return switch (request.getRequestCase()) {
      case REGISTER, MESSAGE, ACCOUNT_STATUS -> {
        Messages.Response.newBuilder()
            .setId(request.getId())
            .setDisconnect(DisconnectOuterClass.Disconnect.newBuilder().setReason("Unsupported operation"))
            .build()
            .writeDelimitedTo(out);
        yield false;
      }

      case KEEPALIVE -> {
        Messages.Response.newBuilder()
            .setId(request.getId())
            .setKeepalive(KeepaliveOuterClass.Keepalive.getDefaultInstance())
            .build()
            .writeDelimitedTo(out);
        yield true;
      }

      case DISCONNECT -> false;
      case REQUEST_NOT_SET -> {
        Messages.Response.newBuilder()
            .setId(request.getId())
            .setDisconnect(DisconnectOuterClass.Disconnect.newBuilder().setReason("Invalid request"))
            .build()
            .writeDelimitedTo(out);
        yield false;
      }
    };
  }

  private record ServerInfo(ServerSocketChannel ch, PublicKey signingPublicKey, PrivateKey signingPrivateKey) {
  }
}
