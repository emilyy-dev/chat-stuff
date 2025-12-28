package ar.emily.chat.stuff;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedByInterruptException;
import java.nio.channels.SocketChannel;
import java.time.Duration;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

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

  void writeWithTimeout0(final ByteBuffer src) throws IOException {
    final Thread writer = Thread.currentThread();
    final var completed = new AtomicBoolean();
    final ScheduledFuture<?> timeoutFuture =
        ForkJoinPool.commonPool().schedule(
            () -> {
              if (completed.compareAndSet(false, true)) {
                writer.interrupt();
              }
            },
            TimeUnit.NANOSECONDS.convert(this.timeout),
            TimeUnit.NANOSECONDS
        );

    try {
      this.ch.write(src);
      if (!completed.compareAndSet(false, true)) {
        // clear interrupt status in case write op completed normally but timeout task ran between that and the CAS op
        Thread.interrupted();
      }
    } catch (final ClosedByInterruptException ex) {
      if (!completed.compareAndSet(false, true)) {
        Thread.interrupted(); // clear interrupt flag in case of read timeout
        throw new WriteTimeoutException();
      } else {
        throw ex;
      }
    } finally {
      completed.set(true);
      timeoutFuture.cancel(false);
    }
  }
}
