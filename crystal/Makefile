SRC=$(shell find src -name '*.cr')
PROTO_DEF=$(wildcard ../proto/*.proto)
PROTO_SRC=$(patsubst ../proto/%.proto,src/proto/%.pb.cr,$(PROTO_DEF))

bin/chat-stuff: Makefile $(SRC) $(PROTO_SRC)
	crystal build src/chat-stuff.cr -o bin/chat-stuff

src/proto/%.pb.cr: ../proto/%.proto
	@mkdir -p $(@D)
	protoc -I ../proto/ --plugin=protoc-gen-crystal=bin/protocr --crystal_out src/proto/ $<

.PHONY: run clean
run: bin/chat-stuff
	bin/chat-stuff

clean:
	rm src/proto/*.pb.cr
	rm bin/chat-stuff
