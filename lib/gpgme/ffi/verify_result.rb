module GPGME
  class VerifyResult
    def self.new_from_struct(struct)
      instance = allocate

      instance.instance_exec do
        @signatures = []

        pointer = struct[:signatures]
        until pointer.null?
          signature = Library::Signature.new pointer

          @signatures << Signature.new_from_struct(signature)

          pointer = signature[:next]
        end
      end

      instance
    end
  end
end
