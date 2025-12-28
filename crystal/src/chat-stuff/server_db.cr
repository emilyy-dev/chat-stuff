require "socket"
require "./openssl"
require "./json"

class Chatty::Client
  struct KnownServer
    include JSON::Serializable

    getter name : String
    @[JSON::Field(converter: Chatty::TCPIPConverter)]
    getter ip : Socket::IPAddress
    @[JSON::Field(converter: Chatty::RSAPEMConverter)]
    getter sign_pub_key : OpenSSL::PKey::RSA

    def initialize(@name, @ip, @sign_pub_key)
    end
  end

  class ServerDB
    getter servers : Array(KnownServer)
    @path : Path

    def initialize(file = "servers.json")
      @path = Path.new file
      if File.exists?(file)
        @servers = File.open(@path) do |f|
          Array(KnownServer).from_json f
        end
      else
        @servers = [] of KnownServer
        save
      end
    end

    def save
      File.open(@path, "w") do |f|
        @servers.to_json f
      end
    end

    def self.interactive_selector(sdb : ServerDB) : KnownServer
      puts "-- server selector --"
      sdb.servers.each_with_index do |s, i|
        puts "#{i + 1}: #{s.name} (#{s.ip}) #{Chatty.fingerprint s.sign_pub_key}"
      end
      puts "n: register new server"
      print "select > "
      choice = read_line
      if choice == "n"
        print "new server name > "
        name = read_line
        print "new server address > "
        address = read_line
        print "new server port > "
        port = read_line.to_i
        puts "new server public signing key (paste)"
        pem = String.build do |str|
          while line = gets(chomp: false)
            str << line
            break if line.includes?("-----END")
          end
        end
        key = PKey::RSA.new pem
        server = Client::KnownServer.new(name, Socket::IPAddress.new(address, port), key)
        sdb.servers.push server
        sdb.save
        return server
      elsif i = choice.to_i?
        return sdb.servers[i - 1]
      else
        raise "no"
      end
    end
  end
end
