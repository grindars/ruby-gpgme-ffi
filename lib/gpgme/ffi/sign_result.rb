module GPGME
  class SignResult
    def self.new_from_struct(struct)
      instance = allocate

      instance.instance_exec do
        @invalid_signers = []

        pointer = struct[:invalid_signers]
        until pointer.null?
          key = Library::InvalidKey.new pointer

          @invalid_signers << InvalidKey.new_from_struct(key)

          pointer = key[:next]
        end

        @signatures = []

        pointer = struct[:signatures]
        until pointer.null?
          signature = Library::NewSignature.new pointer

          @signatures << NewSignature.new_from_struct(signature)

          pointer = key[:next]
        end
      end

      instance
    end
  end
end
