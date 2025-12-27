## Generated from message_request.proto for chat.stuffs.proto
require "protobuf"

require "./handshake.pb.cr"

module Chatty
  module Message
    
    struct MessageRequest
      include ::Protobuf::Message
      
      contract_of "proto3" do
        optional :recipient, :string, 1
      end
    end
    
    struct MessageResponse
      include ::Protobuf::Message
      
      contract_of "proto3" do
        optional :error_message, :string, 1
        optional :hello, Hello, 2
      end
    end
    end
  end
