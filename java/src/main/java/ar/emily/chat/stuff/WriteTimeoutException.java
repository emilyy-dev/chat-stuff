package ar.emily.chat.stuff;

public class WriteTimeoutException extends RuntimeException {

  @java.io.Serial
  private static final long serialVersionUID = 0L;

  public WriteTimeoutException() {
    super(null, null, false, false);
  }
}
