require "./spec_helper"

alias RSA = OpenSSL::PKey::RSA

describe "x509" do
  it "converts private key" do
    pkey = RSA.new String.new data("rsa_private.pem")
    pkey.x509_public.should eq data("rsa_public.der")
  end
  it "converts public key" do
    pkey = RSA.new String.new data("rsa_public.pem")
    pkey.x509_public.should eq data("rsa_public.der")
  end
  it "converts back public key" do
    pkey = RSA.from_x509_public data("rsa_public.der")
    pkey.to_pem.should eq String.new data("rsa_public.pem")
  end
end
