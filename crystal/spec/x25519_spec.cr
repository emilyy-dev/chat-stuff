require "./spec_helper"

X25519_PRIVATE_KEY     = Bytes[112, 30, 183, 213, 243, 4, 148, 142, 152, 159, 212, 16, 178, 101, 31, 234, 60, 109, 74, 131, 231, 29, 226, 172, 174, 10, 83, 80, 18, 93, 112, 93]
X25519_PUBLIC_KEY      = Bytes[190, 1, 168, 92, 39, 211, 30, 82, 66, 57, 88, 184, 67, 86, 207, 225, 188, 130, 47, 245, 223, 88, 66, 99, 184, 66, 62, 163, 168, 32, 0, 72]
X25519_PRIVATE_KEY_PEM = <<-PEM
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIHAet9XzBJSOmJ/UELJlH+o8bUqD5x3irK4KU1ASXXBd
-----END PRIVATE KEY-----

PEM
X25519_PUBLIC_KEY_PEM = <<-PEM
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VuAyEAvgGoXCfTHlJCOVi4Q1bP4byCL/XfWEJjuEI+o6ggAEg=
-----END PUBLIC KEY-----

PEM
include OpenSSL::PKey

describe OpenSSL::PKey::X25519 do
  it "derives public key from private key" do
    priv = X25519.from_bytes X25519_PRIVATE_KEY, true
    priv.public_key_bytes.should eq X25519_PUBLIC_KEY
  end

  it "writes to pem" do
    priv = X25519.from_bytes X25519_PRIVATE_KEY, true
    priv.to_pem.should eq X25519_PRIVATE_KEY_PEM

    pub = X25519.from_bytes X25519_PUBLIC_KEY, false
    pub.to_pem.should eq X25519_PUBLIC_KEY_PEM

    priv.public_key.to_pem.should eq X25519_PUBLIC_KEY_PEM
  end

  it "computes shared secret" do
    alice = X25519.generate
    bob = X25519.generate

    alice_shared = X25519.compute_shared_secret(alice, bob.public_key)
    bob_shared = X25519.compute_shared_secret(bob, alice.public_key)
    alice_shared.should eq bob_shared
  end
end
