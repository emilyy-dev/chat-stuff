package ar.emily.chat.stuff;

public class ReadTimeoutException extends RuntimeException {

  @java.io.Serial
  private static final long serialVersionUID = 0L;

  public ReadTimeoutException() {
    super(null, null, false, false);
  }
}
