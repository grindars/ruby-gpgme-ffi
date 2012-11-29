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

if %x{uname} == "Darwin\n"
  ARCH_CFLAGS="-arch i386 -arch x86_64"
  TARGET_IS_FAT=true
else
  ARCH_CFLAGS=""
  TARGET_IS_FAT=false
end

template = ERB.new File.read("#{SRC}/Makefile.in")
File.write "#{BUILD}/Makefile", template.result(binding)
