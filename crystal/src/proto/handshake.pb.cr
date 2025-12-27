## Generated from handshake.proto for chat.stuffs.proto
require "protobuf"

module Chatty
  module Message
    
    struct AcceptStatus
      include ::Protobuf::Message
      
      contract_of "proto3" do
        optional :deny_reason, :string, 2
      end
    end
    
    struct Hello
      include ::Protobuf::Message
      
      contract_of "proto3" do
        optional :key_xchg_public_key, :bytes, 1
        optional :key_xchg_public_key_signature, :bytes, 2
        optional :nonce, :bytes, 3
        optional :nonce_signature, :bytes, 4
      end
    end
    end
  end
