require "./spec_helper"

HELLO_WORLD_HASH = Bytes[142, 71, 241, 24, 95, 253, 1, 77, 35, 143, 171, 208, 42, 26, 50, 222, 254, 105, 140, 191, 56, 192, 55, 169, 14, 60, 10, 10, 50, 55, 15, 181, 44, 189, 100, 18, 80, 80, 133, 2, 41, 95, 202, 188, 191, 103, 108, 9, 71, 11, 39, 68, 56, 104, 200, 229, 247, 14, 38, 220, 51, 114, 136, 175]
alias SHA3_512 = OpenSSL::Digest::SHA3_512

describe OpenSSL::Digest::SHA3_512 do
  it "hashes" do
    digest = SHA3_512.new
    digest << "Hello, world!"
    digest.final.should eq HELLO_WORLD_HASH
  end
end
