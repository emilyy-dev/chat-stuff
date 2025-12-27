## Generated from account_status.proto for chat.stuffs.proto
require "protobuf"

module Chatty
  module Message
    
    struct AccountStatusRequest
      include ::Protobuf::Message
      
      contract_of "proto3" do
        optional :username, :string, 1
        optional :signature, :bytes, 2
      end
    end
    
    struct AccountStatusResponse
      include ::Protobuf::Message
      
      contract_of "proto3" do
      end
    end
    end
  end
