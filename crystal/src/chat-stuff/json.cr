require "json"
require "uri/json"
require "socket"
require "./openssl"

module Chatty::TCPIPConverter
  def self.from_json(value : JSON::PullParser) : Socket::IPAddress
    Socket::IPAddress.parse URI.new value
  end

  def self.to_json(value : Socket::IPAddress, json : JSON::Builder) : Nil
    URI.new(scheme: "tcp", host: value.address, port: value.port).to_json json
  end
end

module Chatty::RSAPEMConverter
  def self.from_json(value : JSON::PullParser) : OpenSSL::PKey::RSA
    OpenSSL::PKey::RSA.new value.read_string
  end

  def self.to_json(value : OpenSSL::PKey::RSA, json : JSON::Builder) : Nil
    json.scalar value.to_pem
  end
end
