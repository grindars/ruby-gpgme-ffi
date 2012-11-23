module GPGME
  class Ctx
    attr_accessor :context_passphrase_callback
    attr_accessor :context_progress_callback

    class Pointer < FFI::AutoPointer
      def self.release(ptr)
        GPGME::Library.gpgme_release ptr
      end
    end

    def self.new_from_struct(pointer)
      instance = allocate

      instance.instance_exec do
        @context_passphrase_callback = [ nil, nil, nil ]
        @context_progress_callback   = [ nil, nil, nil ]

        @ptr = Pointer.new pointer
      end

      instance
    end

    def release_pointer
      raise ArgumentError, "released ctx" if @ptr.nil?
      @ptr.free
      @ptr = nil
    end

    def context_pointer
      raise "context is already released" if @ptr.nil?
      @ptr
    end
  end
end
