package ar.emily.chat.stuff;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.time.Duration;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

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

  public static int readWithTimeout(final ReadableByteChannel ch, final Duration timeout, final ByteBuffer dst)
      throws IOException {
    final Thread reader = Thread.currentThread();
    final var completed = new AtomicBoolean();
    final ScheduledFuture<?> timeoutFuture =
        ForkJoinPool.commonPool().schedule(
            () -> {
              if (completed.compareAndSet(false, true)) {
                reader.interrupt();
              }
            },
            TimeUnit.NANOSECONDS.convert(timeout),
            TimeUnit.NANOSECONDS
        );

    try {
      final int read = ch.read(dst);
      if (!completed.compareAndSet(false, true)) {
        // clear interrupt status in case read op completed normally but timeout task ran between that and the CAS op
        Thread.interrupted();
      }

      return read;
    } finally {
      completed.set(true);
      timeoutFuture.cancel(false);
    }
  }

  private NetUtil() {
  }
}
