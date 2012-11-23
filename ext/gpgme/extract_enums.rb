#!/usr/bin/env ruby

def rubify(filename, enums)

  state = :source
  fields = {}
  last_field = nil

  enums.puts "  # rubified #{File.basename(filename)}"

  close_enum = ->(name) do

    enums.puts "  # #{$1}"
    fields.each do |key, value|
      enums.puts "  #{key} = #{value}"
    end

    fields = {}
    last_field = nil


    enums.puts ""
  end

  File.open(filename, "r") do |io|
    loop do
      line = io.gets
      break if line.nil?
      line.strip!
      next if line.empty?

      case state
      when :source
        state = :enum if line == "typedef enum"

      when :enum
        state = :enum_block if line == "{"
        if line =~ /^([a-z0-9_]+);$/
          state = :source

          close_enum.call $1
        end

      when :enum_block
        state = :enum if line == "}"

        if line =~ /^([A-Z0-9_a-z]+)\s*=([^,\/]+),?/
          fields[$1] = $2

          last_field = $1
        elsif line =~ /^([A-Z0-9_a-z]+)\s*,?/
          if last_field.nil?
            fields[$1] = 0
          else
            fields[$1] = "#{last_field} + 1"
          end

          last_field = $1
        elsif line =~ /^} ([a-z0-9_]+);$/
          state = :source
          close_enum.call $1
        end
      end

      if line =~ /^#define ([A-Z0-9_a-z]+)\s+([^\/]+)/
        if $1.start_with?("Gpgme") ||
           $1.start_with?("_GPG") ||
           $1 == "GPG_ERROR_H" ||
           $1 == "GPG_ERR_INLINE"

          next
        else
          enums.puts "  #{$1} = #{$2}"
        end
      end
    end
  end

  enums.puts ""
end

enums = File.open(ARGV.pop, "w")

enums.puts "module GPGME"

ARGV.each { |source| rubify source, enums }

enums.puts "end"
