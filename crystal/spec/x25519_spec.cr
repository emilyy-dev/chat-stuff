require "./spec_helper"

include OpenSSL::PKey

describe X25519 do
  private_key = "701eb7d5f304948e989fd410b2651fea3c6d4a83e71de2acae0a5350125d705d".hexbytes
  public_key = "be01a85c27d31e52423958b84356cfe1bc822ff5df584263b8423ea3a8200048".hexbytes

  it "derives public key from private key" do
    priv = X25519.from_bytes private_key, true
    priv.public_key_bytes.should eq public_key
  end

  it "writes to pem" do
    priv = X25519.from_bytes private_key, true
    priv.to_pem.should eq String.new data("x25519_private.pem")

    pub = X25519.from_bytes public_key, false
    pub.to_pem.should eq String.new data("x25519_public.pem")

    priv.public_key.to_pem.should eq String.new data("x25519_public.pem")
  end

  it "computes shared secret" do
    alice = X25519.generate
    bob = X25519.generate

    alice_shared = X25519.compute_shared_secret(alice, bob.public_key)
    bob_shared = X25519.compute_shared_secret(bob, alice.public_key)
    alice_shared.should eq bob_shared
  end
end
