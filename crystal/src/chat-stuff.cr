require "./chat-stuff/openssl"
require "./chat-stuff/io"
require "./chat-stuff/server_db"
require "./proto/*"

module Chatty
  MAGIC   = 0xea68u16
  VERSION =      0u16

  alias Message = Chat::Stuffs::Proto
  include OpenSSL

  def self.load_or_generate_key(file = "key.pem")
    if File.exists?(file)
      key = File.open(file) do |f|
        PKey::RSA.new f
      end
    else
      key = PKey::RSA.new(4096)
      File.open(file, "w") do |f|
        key.to_pem f
      end
    end
    return key
  end

  def self.fingerprint(key : PKey::PKey)
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

  class Client
    Log = ::Log.for "client"
    getter sign_key : PKey::RSA
    @server : KnownServer
    getter socket : TCPSocket

    def initialize(@sign_key, @server)
      @socket = TCPSocket.new
    end

    def connect : Connection
      Log.info { "using signing key #{Chatty.fingerprint @sign_key}" }
      Log.info { "connecting to #{@server.name} (#{@server.ip})" }
      @socket.connect @server.ip
      Log.notice { "Connected to server" }
      @socket.write_bytes(MAGIC, IO::ByteFormat::NetworkEndian)
      @socket.write_bytes(VERSION, IO::ByteFormat::NetworkEndian)
      accept = @socket.read_protobuf_sized(Message::AcceptStatus)
      if accept.has_deny_reason?
        Log.error { "Server rejected us: #{accept.deny_reason}" }
        raise IO::Error.new(accept.deny_reason)
      end

      Connection.new self
    end

    def sign_sha3_512(bytes : Bytes) : Bytes
      @sign_key.sign(Digest::SHA3_512.new, bytes)
    end

    def verify_sha3_512(signature : Bytes, data : Bytes) : Bool
      @server.sign_pub_key.verify(Digest::SHA3_512.new, signature, data)
    end

    def close
      @socket.close
    end
  end

  class Connection
    Log = ::Log.for "connect"
    @client : Client
    @xchg : PKey::X25519
    getter! cipher : CipherStreamIO

    def initialize(@client)
      @xchg = PKey::X25519.generate
    end

    def io : IO
      cipher
    end

    def self.digest_hello(digest, hello)
      digest << hello.key_xchg_public_key
      digest << hello.key_xchg_public_key_signature
      digest << hello.nonce
      digest << hello.nonce_signature
    end

    def handshake : Nil
      Log.info { "handshaking..." }
      nonce = Random::Secure.random_bytes 16

      out_hello = Message::Hello.new
      out_hello.key_xchg_public_key = @xchg.x509_public
      out_hello.key_xchg_public_key_signature = @client.sign_sha3_512(@xchg.x509_public)
      out_hello.nonce = nonce
      out_hello.nonce_signature = @client.sign_sha3_512(nonce)
      @client.socket.write_protobuf_sized out_hello

      in_hello = @client.socket.read_protobuf_sized(Message::Hello)

      unless @client.verify_sha3_512(in_hello.key_xchg_public_key_signature, in_hello.key_xchg_public_key)
        Log.error { "Server key exchange signature doesn't match known signing key!" }
        raise IO::Error.new("Server invalid signature")
      end
      unless @client.verify_sha3_512(in_hello.nonce_signature, in_hello.nonce)
        Log.error { "Server nonce signature doesn't match known signing key!" }
        raise IO::Error.new("Server invalid signature")
      end
      Log.notice { "Server signature verified" }

      hash = Digest::SHA3_512.digest do |digest|
        self.class.digest_hello digest, out_hello
        self.class.digest_hello digest, in_hello
      end

      peer_xchg = PKey::X25519.from_x509_public(in_hello.key_xchg_public_key)
      shared = PKey::X25519.compute_shared_secret(@xchg, peer_xchg)

      local_key = HKDF.derive(Algorithm::SHA512, 32, hash, shared, "#{nonce.hexstring} key")
      local_iv = HKDF.derive(Algorithm::SHA512, 16, hash, shared, "#{nonce.hexstring} iv")
      remote_key = HKDF.derive(Algorithm::SHA512, 32, hash, shared, "#{in_hello.nonce.hexstring} key")
      remote_iv = HKDF.derive(Algorithm::SHA512, 16, hash, shared, "#{in_hello.nonce.hexstring} iv")

      cipher = CipherStreamIO.new(@client.socket, "aes-256-cfb8",
        local_key: local_key, local_iv: local_iv,
        remote_key: remote_key, remote_iv: remote_iv,
      )
      @cipher = cipher
      Log.notice { "Handshake complete, switching to cipher" }
    end

    def send(t)
      Log.info { "Sending #{t.inspect}" }
      io.write_protobuf_sized t
    end

    def recv(t : T.class) : T forall T
      v = io.read_protobuf_sized t
      Log.info { "Received #{v.inspect}" }
      v
    end
  end

  sdb = Client::ServerDB.new
  server = Client::ServerDB.interactive_selector sdb

  client = Client.new(load_or_generate_key, server)
  conn = client.connect
  conn.handshake

  req = Message::Request.new
  msg_out = Message::Keepalive.new
  req.keepalive = msg_out
  req.id = 1
  conn.send req

  msg_in = conn.recv Message::Response

  req = Message::Request.new
  msg_out = Message::Disconnect.new
  msg_out.reason = "bye"
  req.disconnect = msg_out
  req.id = 3
  conn.send req

  msg_in = conn.recv Message::Response
end
