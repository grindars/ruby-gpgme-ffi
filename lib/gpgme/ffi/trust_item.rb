module GPGME
  class TrustItem
    class Pointer < FFI::AutoPointer
      def self.release(ptr)
        GPGME::Library.gpgme_trust_item_unref ptr
      end
    end

    def self.new_from_struct(pointer)
      instance = allocate

      instance.instance_exec do
        @ptr = Pointer.new pointer

        structure = Library::TrustItem.new @ptr
        @keyid = structure[:keyid]
        @type = structure[:type]
        @level = structure[:level]
        @owner_trust = structure[:owner_trust]
        @validity = structure[:validity]
        @name = structure[:name]
      end

      instance
    end

    def context_pointer
      @ptr
    end
  end
end
