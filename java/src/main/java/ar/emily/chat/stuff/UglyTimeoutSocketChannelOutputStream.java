package ar.emily.chat.stuff;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.UndeclaredThrowableException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.time.Duration;
import java.util.concurrent.StructuredTaskScope;

class UglyTimeoutSocketChannelOutputStream extends OutputStream {

  final SocketChannel ch;
  final Duration timeout;
  final byte[] writeOneBuffer = new byte[1];

  UglyTimeoutSocketChannelOutputStream(final SocketChannel ch, final Duration timeout) {
    this.ch = ch;
    this.timeout = timeout;
  }

  @Override
  public void write(final int b) throws IOException {
    this.writeOneBuffer[0] = (byte) b;
    write(this.writeOneBuffer);
  }

  @Override
  public void write(final byte[] b, final int off, final int len) throws IOException {
    writeWithTimeout(ByteBuffer.wrap(b, off, len));
  }

  void writeWithTimeout(final ByteBuffer src) throws IOException {
    while (src.hasRemaining()) {
      writeWithTimeout0(src);
    }
  }

  @SuppressWarnings("preview")
  void writeWithTimeout0(final ByteBuffer src) throws IOException {
    try (
        final var scope =
            StructuredTaskScope.open(StructuredTaskScope.Joiner.awaitAll(), cfg -> cfg.withTimeout(this.timeout))
    ) {
      try {
        final StructuredTaskScope.Subtask<Integer> readTask = scope.fork(() -> this.ch.write(src));
        scope.join();
        if (readTask.state() == StructuredTaskScope.Subtask.State.FAILED) {
          switch (readTask.exception()) {
            case final IOException ex -> throw ex;
            case final RuntimeException ex -> throw ex;
            case final Error ex -> throw ex;
            case final Throwable ex -> throw new UndeclaredThrowableException(ex);
          }
        }
      } catch (final InterruptedException _) {
        Thread.currentThread().interrupt();
      }
    }
  }
}
