require "spec"
require "../src/chat-stuff/*"

def data(*c)
  File.open(Path.new("spec", "data", *c)) do |f|
    f.getb_to_end
  end
end
