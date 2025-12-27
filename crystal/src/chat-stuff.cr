require "./chat-stuff/openssl"
require "./proto/*"

module Chatty
  MAGIC = 0xea68u16
  VERSION = 0u16

  include OpenSSL

  if File.exists?("key.pem")
    key = File.open("key.pem") do |f|
      PKey.read f
    end
  else
    key = PKey::RSA.new(4096)
    File.open("key.pem", "w") do |f|
      key.to_pem f
    end
  end

  p! key.x509_public
  msg = Message::RegisterRequest.new(username: "rymiel", public_signing_key: key.x509_public)
  io = IO::Memory.new
  msg.to_protobuf(io)
  p! io.to_slice.hexstring
end
