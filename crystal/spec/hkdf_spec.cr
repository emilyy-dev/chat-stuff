require "./spec_helper"

SHA_256_KEY = Bytes[42, 196, 54, 159, 82, 89, 150, 248, 222, 19, 115, 31, 86, 34, 79, 52, 223, 14, 76, 150, 202, 169, 59, 253, 236, 207, 35, 123, 80, 57, 200, 219]
SHA_512_KEY = Bytes[104, 140, 105, 158, 237, 196, 80, 173, 43, 106, 174, 21, 79, 248, 242, 152, 230, 249, 60, 35, 231, 111, 163, 36, 11, 65, 213, 242, 207, 152, 81, 154]
include OpenSSL

describe HKDF do
  it "derives 32-bit key with sha-256" do
    k = HKDF.derive(Algorithm::SHA256, 32, "salt".to_slice, "secret".to_slice, "label".to_slice)
    k.should eq SHA_256_KEY
  end

  it "derives 32-bit key with sha-512" do
    k = HKDF.derive(Algorithm::SHA512, 32, "salt".to_slice, "secret".to_slice, "label".to_slice)
    k.should eq SHA_512_KEY
  end
end
