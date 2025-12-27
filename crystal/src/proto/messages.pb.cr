## Generated from messages.proto for chat.stuffs.proto
require "protobuf"

require "./register.pb.cr"
require "./account_status.pb.cr"
require "./message_request.pb.cr"

module Chatty
  module Message
    
    struct Request
      include ::Protobuf::Message
      
      contract_of "proto3" do
        optional :id, :uint64, 1
        optional :register, RegisterRequest, 2
        optional :message, MessageRequest, 3
        optional :account_status, AccountStatusRequest, 4
      end
    end
    
    struct Response
      include ::Protobuf::Message
      
      contract_of "proto3" do
        optional :id, :uint64, 1
        optional :register, RegisterResponse, 2
        optional :message, MessageResponse, 3
        optional :account_status, AccountStatusResponse, 4
      end
    end
    end
  end
