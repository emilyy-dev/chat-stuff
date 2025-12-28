require "./chat-stuff/openssl"
require "./proto/*"

module Chatty
  MAGIC   = 0xea68u16
  VERSION =      0u16

  include OpenSSL

  class CipherStreamIO < IO
    getter read_cipher : Cipher
    getter write_cipher : Cipher

    def initialize(@io : IO, cipher_method : String, local_iv : Bytes, local_key : Bytes, remote_iv : Bytes, remote_key : Bytes)
      @read_cipher = Cipher.new cipher_method
      @read_cipher.decrypt
      @read_cipher.key = local_key
      @read_cipher.iv = local_iv
      @write_cipher = Cipher.new cipher_method
      @write_cipher.encrypt
      @write_cipher.key = remote_key
      @write_cipher.iv = remote_iv
    end

    def read(slice : Bytes)
      upstream_size = @io.read slice
      upstream = slice[0, upstream_size]
      o = @read_cipher.update upstream
      slice.copy_from o
      upstream_size
    end

    def write(slice : Bytes) : Nil
      @io.write @write_cipher.update(slice)
    end

    def flush
      @io.flush
    end
  end

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

  def self.write_sized(t : T, io : IO) forall T
    buf = t.to_protobuf
    Protobuf::Buffer.new(io).write_int32(buf.size)
    io.write buf.to_slice
    io.flush
  end

  def self.read_sized(t : T.class, io : IO) forall T
    size = Protobuf::Buffer.new(io).read_uint32.not_nil!
    t.from_protobuf(IO::Sized.new(io, size))
  end

  if File.exists?("key.pem")
    sign_key = File.open("key.pem") do |f|
      PKey::RSA.new f
    end
  else
    sign_key = PKey::RSA.new(4096)
    File.open("key.pem", "w") do |f|
      sign_key.to_pem f
    end
  end
  puts "Using signing key #{fingerprint(sign_key)}"

  server_ip = gets.not_nil!
  server_port = gets.not_nil!.to_i32
  server = TCPSocket.new(server_ip, server_port)
  puts "Connected"
  client = IO::Hexdump.new(server, read: true, write: true)
  client.write_bytes(MAGIC, IO::ByteFormat::NetworkEndian)
  client.write_bytes(VERSION, IO::ByteFormat::NetworkEndian)

  fresh = PKey::X25519.generate

  puts "Fresh public key"
  puts fresh.x509_public.hexstring
  fresh_signature = sign_key.sign(Digest::SHA3_512.new, fresh.x509_public)
  puts "Fresh public key signature"
  puts fresh_signature.hexstring

  nonce = Random::Secure.random_bytes 16
  puts "Nonce"
  puts nonce.hexstring
  nonce_signature = sign_key.sign(Digest::SHA3_512.new, nonce)
  puts "Nonce signature"
  puts nonce_signature.hexstring

  puts "Hello"
  msg = Message::Hello.new
  msg.key_xchg_public_key = fresh.x509_public
  msg.key_xchg_public_key_signature = fresh_signature
  msg.nonce = nonce
  msg.nonce_signature = nonce_signature
  write_sized(msg, client)

  puts "Accept status"
  msg_in = read_sized(Message::AcceptStatus, client)
  p! msg_in

  puts "Hello in"
  msg_in = read_sized(Message::Hello, client)
  p! msg_in

  def self.add_to_digest(digest, hello)
    digest << hello.key_xchg_public_key.not_nil!
    digest << hello.key_xchg_public_key_signature.not_nil!
    digest << hello.nonce.not_nil!
    digest << hello.nonce_signature.not_nil!
  end

  digest = Digest::SHA3_512.new
  add_to_digest digest, msg
  add_to_digest digest, msg_in
  hash = digest.final

  remote_pubkey = PKey::X25519.from_x509_public(msg_in.key_xchg_public_key.not_nil!)
  shared = PKey::X25519.compute_shared_secret(fresh, remote_pubkey)
  puts shared.hexstring

  local_key = HKDF.derive(Algorithm::SHA512, 32, hash, shared, "#{nonce.hexstring} key".to_slice)
  local_iv = HKDF.derive(Algorithm::SHA512, 16, hash, shared, "#{nonce.hexstring} iv".to_slice)
  remote_key = HKDF.derive(Algorithm::SHA512, 32, hash, shared, "#{msg_in.nonce.not_nil!.hexstring} key".to_slice)
  remote_iv = HKDF.derive(Algorithm::SHA512, 16, hash, shared, "#{msg_in.nonce.not_nil!.hexstring} iv".to_slice)

  p! local_key.hexstring, local_iv.hexstring, remote_key.hexstring, remote_iv.hexstring

  cipher = CipherStreamIO.new(client, "aes-256-cfb8", local_iv, local_key, remote_iv, remote_key)
  msg = Message::AcceptStatus.new
  msg.deny_reason = "I love you! I love you! I love you! I love you! I love you! I love you!"
  write_sized(msg, cipher)

  msg_in = read_sized(Message::AcceptStatus, cipher)
  p! msg_in

end
