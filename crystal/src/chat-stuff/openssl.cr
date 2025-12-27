require "openssl"
require "openssl_ext"
require "digest"

class Digest::SHA3_512 < ::OpenSSL::Digest
  extend ClassMethods

  def initialize
    super("SHA3-512")
  end

  protected def initialize(ctx : LibCrypto::EVP_MD_CTX)
    super("SHA3-512", ctx)
  end

  def dup
    self.class.new(dup_ctx)
  end
end

lib LibCrypto
  NID_X25519      = 1034
  NID_hkdf        = 1036
  EVP_PKEY_X25519 = NID_X25519
  EVP_PKEY_HKDF   = NID_hkdf

  fun evp_pkey_ctx_new_id = EVP_PKEY_CTX_new_id(id : LibC::Int, engine : Engine) : EVP_PKEY_CTX
  fun evp_pkey_ctx_set_hkdf_md = EVP_PKEY_CTX_set_hkdf_md(pctx : EVP_PKEY_CTX, md : EVP_MD) : LibC::Int
  fun evp_pkey_ctx_set_salt = EVP_PKEY_CTX_set1_hkdf_salt(pctx : EVP_PKEY_CTX, s : Char*, len : LibC::Int) : LibC::Int
  fun evp_pkey_ctx_set_key = EVP_PKEY_CTX_set1_hkdf_key(pctx : EVP_PKEY_CTX, s : Char*, len : LibC::Int) : LibC::Int
  fun evp_pkey_ctx_add_info = EVP_PKEY_CTX_add1_hkdf_info(pctx : EVP_PKEY_CTX, s : Char*, len : LibC::Int) : LibC::Int

  fun evp_pkey_q_keygen = EVP_PKEY_Q_keygen(libctx : Void*, propq : Char*, type : Char*, ...) : EvpPKey*

  fun evp_pkey_get_raw_public_key = EVP_PKEY_get_raw_public_key(pkey : EvpPKey*, pub : Char*, len : LibC::SizeT*) : LibC::Int
  fun evp_pkey_get_raw_private_key = EVP_PKEY_get_raw_private_key(pkey : EvpPKey*, priv : Char*, len : LibC::SizeT*) : LibC::Int

  fun evp_pkey_new_raw_public_key = EVP_PKEY_new_raw_public_key(type : LibC::Int, e : Engine, key : Char*, keylen : LibC::SizeT) : EvpPKey*
  fun evp_pkey_new_raw_private_key = EVP_PKEY_new_raw_private_key(type : LibC::Int, e : Engine, key : Char*, keylen : LibC::SizeT) : EvpPKey*

  fun i2d_pubkey = i2d_PUBKEY(a : EvpPKey*, pp : Char**) : LibC::Int
end

module OpenSSL::HKDF
  def self.derive(algo : Algorithm, size : UInt64, salt : Bytes, secret : Bytes, label : Bytes) : Bytes
    # unsigned char out[10];
    # size_t outlen = sizeof(out);
    buffer = Bytes.new(size)
    pctx = LibCrypto.evp_pkey_ctx_new_id(LibCrypto::EVP_PKEY_HKDF, nil)
    raise OpenSSL::Error.new("EVP_PKEY_CTX_new_id failed") if pctx.null?

    begin
      rc = LibCrypto.evp_pkey_derive_init(pctx)
      raise OpenSSL::Error.new("EVP_PKEY_derive_init failed") unless rc == 1

      rc = LibCrypto.evp_pkey_ctx_set_hkdf_md(pctx, algo.to_evp)
      raise OpenSSL::Error.new("EVP_PKEY_CTX_set_hkdf_md failed") unless rc == 1

      rc = LibCrypto.evp_pkey_ctx_set_salt(pctx, salt.to_unsafe, salt.size)
      raise OpenSSL::Error.new("EVP_PKEY_CTX_set1_hkdf_salt failed") unless rc == 1

      rc = LibCrypto.evp_pkey_ctx_set_key(pctx, secret.to_unsafe, secret.size)
      raise OpenSSL::Error.new("EVP_PKEY_CTX_set1_hkdf_key failed") unless rc == 1

      rc = LibCrypto.evp_pkey_ctx_add_info(pctx, label.to_unsafe, label.size)
      raise OpenSSL::Error.new("EVP_PKEY_CTX_add1_hkdf_info failed") unless rc == 1

      rc = LibCrypto.evp_pkey_derive(pctx, buffer.to_unsafe, pointerof(size))
      raise OpenSSL::Error.new("EVP_PKEY_derive failed") unless rc == 1

      buffer
    ensure
      LibCrypto.evp_pkey_ctx_free(pctx)
    end
  end
end

module OpenSSL::PKey
  class X25519 < PKey
    def private_key_bytes : Bytes
      out_len = LibC::SizeT.new(0)
      rc = LibCrypto.evp_pkey_get_raw_private_key(@pkey, Pointer(UInt8).null, pointerof(out_len))
      raise OpenSSL::Error.new("EVP_PKEY_get_raw_private_key(size) failed") unless rc == 1
      raise OpenSSL::Error.new("unexpected zero length from EVP_PKEY_get_raw_private_key") if out_len == 0

      priv = Bytes.new(out_len)
      rc = LibCrypto.evp_pkey_get_raw_private_key(@pkey, priv.to_unsafe, pointerof(out_len))
      raise OpenSSL::Error.new("EVP_PKEY_get_raw_private_key failed") unless rc == 1

      priv
    end

    def public_key_bytes : Bytes
      out_len = LibC::SizeT.new(0)
      rc = LibCrypto.evp_pkey_get_raw_public_key(@pkey, Pointer(UInt8).null, pointerof(out_len))
      raise OpenSSL::Error.new("EVP_PKEY_get_raw_public_key(size) failed") unless rc == 1
      raise OpenSSL::Error.new("unexpected zero length from EVP_PKEY_get_raw_public_key") if out_len == 0

      public = Bytes.new(out_len)
      rc = LibCrypto.evp_pkey_get_raw_public_key(@pkey, public.to_unsafe, pointerof(out_len))
      raise OpenSSL::Error.new("EVP_PKEY_get_raw_public_key failed") unless rc == 1

      public
    end

    def public_key : X25519
      X25519.from_bytes(public_key_bytes, false)
    end

    def self.generate
      evp_pkey = LibCrypto.evp_pkey_q_keygen(nil, nil, "X25519")
      raise OpenSSL::Error.new("EVP_PKEY_Q_keygen failed") if evp_pkey.null?
      X25519.new evp_pkey, true
    end

    def self.from_bytes(bytes : Bytes, is_private : Bool)
      if is_private
        pkey = LibCrypto.evp_pkey_new_raw_private_key(LibCrypto::EVP_PKEY_X25519, nil, bytes.to_unsafe, bytes.size)
      else
        pkey = LibCrypto.evp_pkey_new_raw_public_key(LibCrypto::EVP_PKEY_X25519, nil, bytes.to_unsafe, bytes.size)
      end
      X25519.new pkey, is_private
    end

    def self.compute_shared_secret(
      private_key : OpenSSL::PKey::X25519,
      peer_public_key : OpenSSL::PKey::X25519,
    ) : Bytes
      priv_pkey = private_key.to_unsafe
      peer_pkey = peer_public_key.to_unsafe
      raise OpenSSL::Error.new("nil private EVP_PKEY") if priv_pkey.null?
      raise OpenSSL::Error.new("nil peer EVP_PKEY") if peer_pkey.null?

      ctx = LibCrypto.evp_pkey_ctx_new(priv_pkey, nil)
      raise OpenSSL::Error.new("EVP_PKEY_CTX_new failed") if ctx.null?

      begin
        rc = LibCrypto.evp_pkey_derive_init(ctx)
        raise OpenSSL::Error.new("EVP_PKEY_derive_init failed") unless rc == 1

        rc = LibCrypto.evp_pkey_derive_set_peer(ctx, peer_pkey)
        raise OpenSSL::Error.new("EVP_PKEY_derive_set_peer failed (curve mismatch or invalid key)") unless rc == 1

        out_len = LibC::SizeT.new(0)
        rc = LibCrypto.evp_pkey_derive(ctx, Pointer(UInt8).null, pointerof(out_len))
        raise OpenSSL::Error.new("EVP_PKEY_derive(size) failed") unless rc == 1
        raise OpenSSL::Error.new("unexpected zero length from derive") if out_len == 0

        secret = Bytes.new(out_len)
        rc = LibCrypto.evp_pkey_derive(ctx, secret.to_unsafe, pointerof(out_len))
        raise OpenSSL::Error.new("EVP_PKEY_derive failed") unless rc == 1

        secret
      ensure
        LibCrypto.evp_pkey_ctx_free(ctx)
      end
    end
  end

  class PKey
    def x509_public : Bytes
      rc = LibCrypto.i2d_pubkey(@pkey, nil)
      raise OpenSSL::Error.new("i2d_PUBKEY(size) failed") if rc < 0

      buffer = Bytes.new(rc)
      ptr = buffer.to_unsafe
      rc = LibCrypto.i2d_pubkey(@pkey, pointerof(ptr))
      raise OpenSSL::Error.new("i2d_PUBKEY failed") if rc < 0

      return buffer
    end
  end
end
