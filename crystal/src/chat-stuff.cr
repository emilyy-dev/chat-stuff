require "./chat-stuff/openssl"
require "./proto/*"

module Chatty
  MAGIC   = 0xea68u16
  VERSION =      0u16

  include OpenSSL

  def self.fingerprint(key : PKey::RSA)
    md5 = Digest::MD5.digest(key.x509_public)
    flag = false
    String.build do |str|
      md5.each do |v|
        str << ':' if flag
        str << v.to_s(16, precision: 2)
        flag = true
      end
    end
  end

  if File.exists?("key.pem")
    key = File.open("key.pem") do |f|
      PKey::RSA.new f
    end
  else
    key = PKey::RSA.new(4096)
    File.open("key.pem", "w") do |f|
      key.to_pem f
    end
  end

  puts "Using key #{fingerprint(key)}"
  msg = Message::RegisterRequest.new(username: "rymiel", public_signing_key: key.x509_public)
  io = IO::Memory.new
  msg.to_protobuf(io)
  p! io.to_slice.hexstring
end
