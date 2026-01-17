package ar.emily.chat.stuff;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.time.Duration;

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
      NetUtil.writeWithTimeout(this.ch, this.timeout, src);
    }
  }
}
