module GPGME
  class Data
    class Pointer < FFI::AutoPointer
      def self.release(ptr)
        GPGME::Library.gpgme_data_release ptr
      end
    end

    def self.new_from_struct(pointer, cbs = nil)
      instance = allocate

      instance.instance_exec do
        @ptr = Pointer.new pointer
        @cbs = cbs
      end

      instance
    end

    def context_pointer
      @ptr
    end
  end
end
