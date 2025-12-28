package ar.emily.chat.stuff;

import java.io.EOFException;
import java.io.IOException;
import java.lang.reflect.UndeclaredThrowableException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.time.Duration;
import java.util.concurrent.StructuredTaskScope;

public final class NetUtil {

  public static ByteBuffer readNBytes(final ReadableByteChannel ch, final Duration timeout, final ByteBuffer dst)
      throws IOException {
    dst.clear();
    int read = 0;
    while (dst.hasRemaining() && read != -1) {
      read = readWithTimeout(ch, timeout, dst);
    }

    if (read == -1) {
      throw new EOFException();
    }

    return dst.flip();
  }

  @SuppressWarnings("preview")
  public static int readWithTimeout(final ReadableByteChannel ch, final Duration timeout, final ByteBuffer dst)
      throws IOException {
    try (
        final var scope =
            StructuredTaskScope.open(StructuredTaskScope.Joiner.awaitAll(), cfg -> cfg.withTimeout(timeout))
    ) {
      try {
        final StructuredTaskScope.Subtask<Integer> readTask = scope.fork(() -> ch.read(dst));
        scope.join();
        if (readTask.state() == StructuredTaskScope.Subtask.State.SUCCESS) {
          return readTask.get();
        } else if (readTask.state() == StructuredTaskScope.Subtask.State.FAILED) {
          switch (readTask.exception()) {
            case final IOException ex -> throw ex;
            case final RuntimeException ex -> throw ex;
            case final Error ex -> throw ex;
            case final Throwable ex -> throw new UndeclaredThrowableException(ex);
          }
        } else {
          throw new IllegalStateException();
        }
      } catch (final InterruptedException _) {
        Thread.currentThread().interrupt();
        return -1;
      }
    }
  }

  private NetUtil() {
  }
}
