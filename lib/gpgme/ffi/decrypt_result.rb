module GPGME
  class DecryptResult
    def self.new_from_struct(struct)
      instance = allocate

      instance.instance_exec do
        @unsupported_algorithm = struct[:unsupported_algorithm]
        @wrong_key_usage       = (struct[:flags] >> 0) & 1
      end

      instance
    end
  end
end