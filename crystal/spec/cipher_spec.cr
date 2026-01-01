require "./spec_helper"

include OpenSSL::PKey

describe Chatty::CipherStreamIO do
  it "roundtrips" do
    alice_read, bob_write = IO.pipe
    bob_read, alice_write = IO.pipe
    alice_io = IO::Stapled.new(alice_read, alice_write)
    bob_io = IO::Stapled.new(bob_read, bob_write)

    alice_io.puts "Hello, Bob!"
    bob_io.puts "Hello, Alice!"
    alice_io.gets.should eq "Hello, Alice!"
    bob_io.gets.should eq "Hello, Bob!"

    100.times do
      secret = Random::Secure.random_bytes(32)

      alice_key = HKDF.derive(Algorithm::SHA512, 32, "", secret, "alice key")
      alice_iv = HKDF.derive(Algorithm::SHA512, 16, "", secret, "alice iv")
      bob_key = HKDF.derive(Algorithm::SHA512, 32, "", secret, "bob key")
      bob_iv = HKDF.derive(Algorithm::SHA512, 16, "", secret, "bob iv")

      alice_cipher = Chatty::CipherStreamIO.new(alice_io, "aes-256-cfb8",
        local_key: alice_key, local_iv: alice_iv,
        remote_key: bob_key, remote_iv: bob_iv,
      )
      bob_cipher = Chatty::CipherStreamIO.new(bob_io, "aes-256-cfb8",
        local_key: bob_key, local_iv: bob_iv,
        remote_key: alice_key, remote_iv: alice_iv,
      )

      buffer = Bytes.new 1024
      buffer2 = Bytes.new 1024

      # Alice -> Bob
      Random::Secure.random_bytes buffer
      alice_cipher.write buffer
      bob_cipher.read_fully buffer2
      buffer2.should eq buffer

      # Bob -> Alice
      Random::Secure.random_bytes buffer
      bob_cipher.write buffer
      alice_cipher.read_fully buffer2
      buffer2.should eq buffer
    end
  end
end
