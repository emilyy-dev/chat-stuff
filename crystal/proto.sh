#!/bin/sh
crystal build lib/protobuf/bin/protoc-gen-crystal.cr -o ~/.local/bin/protoc-gen-crystal
rm src/proto/*.pb.cr
PROTOBUF_NS="Chatty::Message" STRIP_FROM_PACKAGE="chat.stuffs.proto" protoc -I ../proto/ --crystal_out src/proto/ ../proto/*.proto
