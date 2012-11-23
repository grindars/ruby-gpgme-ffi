module GPGME
  class ImportResult
    def self.new_from_struct(struct)
      instance = allocate

      instance.instance_exec do
        @considered       = struct[:considered]
        @no_user_id       = struct[:no_user_id]
        @imported         = struct[:imported]
        @imported_rsa     = struct[:imported_rsa]
        @unchanged        = struct[:unchanged]
        @new_user_ids     = struct[:new_user_ids]
        @new_sub_keys     = struct[:new_sub_keys]
        @new_signatures   = struct[:new_signatures]
        @new_revocations  = struct[:new_revocations]
        @secret_read      = struct[:secret_read]
        @secret_imported  = struct[:secret_imported]
        @secret_unchanged = struct[:secret_unchanged]
        @not_imported     = struct[:not_imported]

        @imports = []
        pointer = struct[:imports]
        until pointer.null?
          status = Library::ImportStatus.new pointer

          @imports << ImportStatus.new_from_struct(status)

          pointer = status[:next]
        end
      end

      instance
    end
  end
end
