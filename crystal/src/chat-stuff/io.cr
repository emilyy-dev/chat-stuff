require "protobuf"

class IO
  def write_protobuf_sized(t : T) : Nil forall T
    buf = t.to_protobuf
    Protobuf::Buffer.new(self).write_int32(buf.size)
    IO.copy buf, self
    self.flush
  end

  def read_protobuf_sized(t : T.class) : T forall T
    size = Protobuf::Buffer.new(self).read_uint32.not_nil!
    t.from_protobuf(IO::Sized.new(self, size))
  end
end

module Chatty
  class CipherStreamIO < IO
    getter read_cipher : Cipher
    getter write_cipher : Cipher

    def initialize(@io : IO, cipher_method : String, *, local_iv : Bytes, local_key : Bytes, remote_iv : Bytes, remote_key : Bytes)
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
end
