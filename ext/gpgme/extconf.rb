require "erb"

BUILD   = Dir::pwd
SRC     = File.expand_path(File.dirname(__FILE__))
PREFIX  = "#{BUILD}/dst"

template = ERB.new File.read("#{SRC}/Makefile.in")
File.write "#{BUILD}/Makefile", template.result(binding)
