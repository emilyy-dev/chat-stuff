package ar.emily.chat.stuff;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.time.Duration;

class UglyTimeoutSocketChannelInputStream extends InputStream {

  final SocketChannel ch;
  final Duration timeout;
  final byte[] readOneBuffer = new byte[1];

  UglyTimeoutSocketChannelInputStream(final SocketChannel ch, final Duration timeout) {
    this.ch = ch;
    this.timeout = timeout;
  }

  @Override
  public int read() throws IOException {
    final int bytesRead = read(this.readOneBuffer);
    return bytesRead == -1 ? -1 : this.readOneBuffer[0] & 0xff;
  }

  @Override
  public int read(final byte[] b, final int off, final int len) throws IOException {
    return NetUtil.readWithTimeout(this.ch, this.timeout, ByteBuffer.wrap(b, off, len));
  }
}
