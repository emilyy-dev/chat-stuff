import org.jspecify.annotations.NullMarked;

@NullMarked
module ar.emily.chat.stuff {
  exports ar.emily.chat.stuff;

  requires com.google.protobuf;
  requires org.jspecify;
  requires org.slf4j;
}
