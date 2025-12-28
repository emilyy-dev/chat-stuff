package ar.emily.chat.stuff;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class LoggerUtil {

  private static final StackWalker STACK_WALKER = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE);

  public static Logger getLogger() {
    return LoggerFactory.getLogger(STACK_WALKER.getCallerClass());
  }

  private LoggerUtil() {
  }
}
