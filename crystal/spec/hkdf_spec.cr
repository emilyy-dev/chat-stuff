require "./spec_helper"

include OpenSSL

describe HKDF do
  it "derives 32-bit key with sha-256" do
    sha_256_key = "2ac4369f525996f8de13731f56224f34df0e4c96caa93bfdeccf237b5039c8db".hexbytes
    k = HKDF.derive(Algorithm::SHA256, 32, "salt".to_slice, "secret".to_slice, "label".to_slice)
    k.should eq sha_256_key
  end

  it "derives 32-bit key with sha-512" do
    sha_512_key = "688c699eedc450ad2b6aae154ff8f298e6f93c23e76fa3240b41d5f2cf98519a".hexbytes
    k = HKDF.derive(Algorithm::SHA512, 32, "salt".to_slice, "secret".to_slice, "label".to_slice)
    k.should eq sha_512_key
  end
end
