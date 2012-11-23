module GPGME
  class UserID
    def self.new_from_struct(struct)
      instance = allocate

      instance.instance_exec do
        @revoked  = (struct[:flags] >> 0) & 1
        @invalid  = (struct[:flags] >> 1) & 1
        @validity = struct[:validity]
        @uid      = struct[:uid]
        @name     = struct[:name]
        @email    = struct[:email]
        @comment  = struct[:comment]

        @signatures = []
        pointer = struct[:signatures]

        until pointer.null?
          signature = Library::KeySig

          @signatures << KeySig.new_from_struct(signature)

          pointer = signature[:next]
        end
      end

      instance
    end
  end
end
