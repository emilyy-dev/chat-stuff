package ar.emily.chat.stuff;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;

public final class NetUtil {

  public static ByteBuffer readNBytes(final ReadableByteChannel ch, final ByteBuffer dst)
      throws IOException {
    dst.clear();
    while (dst.hasRemaining()) {
      ch.read(dst);
    }

    return dst.flip();
  }

  private NetUtil() {
  }
}
