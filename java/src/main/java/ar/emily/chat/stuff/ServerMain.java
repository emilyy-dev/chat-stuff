package ar.emily.chat.stuff;

import module java.base;
import ar.emily.chat.stuff.proto.ClientHello;
import ar.emily.chat.stuff.proto.MessageRequest;
import ar.emily.chat.stuff.proto.MessageRequestResponse;
import ar.emily.chat.stuff.proto.ServerHello;

@SuppressWarnings("preview")
public final class ServerMain {

  private static final int MAGIC_NUMBER = 0xea6851df;
  private static final short PROTOCOL_VERSION = 0;

  void main() throws InterruptedException {
    try (final var scope = StructuredTaskScope.open()) {
      scope.fork(() -> {
        try {
          serverAcceptLoop();
        } catch (final InterruptedException _) {
          Thread.currentThread().interrupt();
        }
      });

      scope.join();
    }
  }

  private void serverAcceptLoop() throws InterruptedException {
    try (final var scope = StructuredTaskScope.open(StructuredTaskScope.Joiner.awaitAll())) {
      try (final var ssc = ServerSocketChannel.open()) {
        while (true) {
          final SocketChannel client = ssc.accept();
          scope.fork(() -> {
            SocketAddress remoteAddress = null;
            try {
              remoteAddress = client.getRemoteAddress();
              handleClient(client);
            } catch (final Exception ex) {
              synchronized (System.err) {
                System.err.println("Unexpected error handling client " + remoteAddress);
                ex.printStackTrace(System.err);
              }
            }
          });
        }
      } catch (final ClosedByInterruptException _) {
      } catch (final AsynchronousCloseException _) {
        scope.join();
      } catch (final IOException ex) {
        scope.join();
        throw new UncheckedIOException(ex);
      }
    }
  }

  private void handleClient(final SocketChannel ch) throws IOException {
  }
}
