module GPGME
  class Key
    class Pointer < FFI::AutoPointer
      def self.release(ptr)
        Library.gpgme_key_unref ptr
      end
    end

    def self.new_from_struct(pointer)
      instance = allocate

      instance.instance_exec do
        @ptr = Pointer.new pointer

        struct = Library::Key.new @ptr
        @keylist_mode     = struct[:keylist_mode]
        @revoked          = (struct[:flags] >> 0) & 1
        @expired          = (struct[:flags] >> 1) & 1
        @disabled         = (struct[:flags] >> 2) & 1
        @invalid          = (struct[:flags] >> 3) & 1
        @can_encrypt      = (struct[:flags] >> 4) & 1
        @can_sign         = (struct[:flags] >> 5) & 1
        @can_certify      = (struct[:flags] >> 6) & 1
        @secret           = (struct[:flags] >> 7) & 1
        @can_authenticate = (struct[:flags] >> 8) & 1
        @protocol         = struct[:protocol]
        @issuer_serial    = struct[:issuer_serial]
        @issuer_name      = struct[:issuer_name]
        @chain_id         = struct[:chain_id]
        @owner_trust      = struct[:owner_trust]

        @subkeys = []
        pointer = struct[:subkeys]
        until pointer.null?
          subkey = Library::SubKey.new pointer

          @subkeys << SubKey.new_from_struct(subkey)

          pointer = subkey[:next]
        end

        @uids = []
        pointer = struct[:uids]
        until pointer.null?
          uid = Library::UserID.new pointer

          @uids << UserID.new_from_struct(uid)

          pointer = uid[:next]
        end
      end

      instance
    end

    def context_pointer
      @ptr
    end
  end
end
