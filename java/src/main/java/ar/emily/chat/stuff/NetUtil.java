package ar.emily.chat.stuff;

import org.intellij.lang.annotations.MagicConstant;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.WritableByteChannel;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

public final class NetUtil {

  public static <CH extends SelectableChannel & ReadableByteChannel>
  ByteBuffer readNBytes(final CH ch, final Duration timeout, final ByteBuffer dst) throws IOException {
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

  public static <CH extends SelectableChannel & ReadableByteChannel>
  int readWithTimeout(final CH ch, final Duration timeout, final ByteBuffer dst) throws IOException {
    synchronized (ch.blockingLock()) {
      try (var _ = nonBlockingBlock(ch)) {
        final @ChannelOps int readyOps = awaitReady(ch, timeout, SelectionKey.OP_READ);
        if (readyOps == SelectionKey.OP_READ) {
          return ch.read(dst);
        }

        throw new ReadTimeoutException();
      }
    }
  }

  public static <CH extends SelectableChannel & WritableByteChannel>
  int writeWithTimeout(final CH ch, final Duration timeout, final ByteBuffer src) throws IOException {
    synchronized (ch.blockingLock()) {
      try (var _ = nonBlockingBlock(ch)) {
        final @ChannelOps int readyOps = awaitReady(ch, timeout, SelectionKey.OP_WRITE);
        if (readyOps == SelectionKey.OP_WRITE) {
          return ch.write(src);
        }

        throw new WriteTimeoutException();
      }
    }
  }

  private static @ChannelOps int
  awaitReady(final SelectableChannel ch, final Duration timeout, final @ChannelOps int ops) throws IOException {
    assert Thread.holdsLock(ch.blockingLock());
    assert !ch.isBlocking();
    try (final var selector = ch.provider().openSelector()) {
      final SelectionKey key = ch.register(selector, ops);
      selector.select(TimeUnit.MILLISECONDS.convert(timeout));
      return key.readyOps();
    }
  }

  private static Closeable nonBlockingBlock(final SelectableChannel ch) throws IOException {
    assert Thread.holdsLock(ch.blockingLock());
    final boolean wasBlocking = ch.isBlocking();
    ch.configureBlocking(false);
    return () -> ch.configureBlocking(wasBlocking);
  }

  @Target(ElementType.TYPE_USE)
  @Retention(RetentionPolicy.CLASS)
  @MagicConstant(flagsFromClass = SelectionKey.class)
  public @interface ChannelOps {
  }

  private NetUtil() {
  }
}
