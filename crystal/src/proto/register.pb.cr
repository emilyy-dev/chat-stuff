## Generated from register.proto for chat.stuffs.proto
require "protobuf"

module Chatty
  module Message
    
    struct RegisterRequest
      include ::Protobuf::Message
      
      contract_of "proto3" do
        optional :username, :string, 1
        optional :public_signing_key, :bytes, 2
      end
    end
    
    struct RegisterResponse
      include ::Protobuf::Message
      
      contract_of "proto3" do
        optional :error_message, :string, 1
      end
    end
    end
  end
