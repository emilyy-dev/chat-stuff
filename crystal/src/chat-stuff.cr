require "./chat-stuff/openssl"
require "./proto/*"

module Chatty
  VERSION = "0.1.0"

  include OpenSSL

  msg = Message::Hello.new(key_xchg_public_key: PKey::X25519.generate.public_key_bytes)
  io = IO::Memory.new
  msg.to_protobuf(io)
  p! io.to_slice.hexstring
end
