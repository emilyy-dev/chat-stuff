require "./spec_helper"

alias SHA3_512 = OpenSSL::Digest::SHA3_512

describe SHA3_512 do
  it "hashes" do
    hash = "8e47f1185ffd014d238fabd02a1a32defe698cbf38c037a90e3c0a0a32370fb52cbd641250508502295fcabcbf676c09470b27443868c8e5f70e26dc337288af".hexbytes
    digest = SHA3_512.new
    digest << "Hello, world!"
    digest.final.should eq hash
  end
end
