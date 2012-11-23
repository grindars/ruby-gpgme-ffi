module GPGME
  class EncryptResult
    def self.new_from_struct(struct)
      instance = allocate

      instance.instance_exec do
        @invalid_recipients = []

        pointer = struct[:invalid_recipients]
        until pointer.null?
          key = Library::InvalidKey.new pointer

          @invalid_recipients << InvalidKey.new_from_struct(key)

          pointer = key[:next]
        end
      end

      instance
    end
  end
end
