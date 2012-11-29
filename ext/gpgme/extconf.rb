require "erb"

BUILD   = Dir::pwd
SRC     = File.expand_path(File.dirname(__FILE__))
PREFIX  = "#{BUILD}/dst"

if !system("gpg", "--version")
  STDERR.puts "GPG is not available. Please read README first."
  STDERR.puts "tl;dr: install gpg and gpg-agent."
  exit 1
end

system "gpg-agent", "--version"

template = ERB.new File.read("#{SRC}/Makefile.in")
File.write "#{BUILD}/Makefile", template.result(binding)
