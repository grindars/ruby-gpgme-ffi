module GPGME
  module Meta
    def self.ffize_value(arg)
      if arg.respond_to?(:context_pointer)
        arg.context_pointer

      elsif arg.kind_of?(String)
        FFI::MemoryPointer.from_string arg

      elsif arg.kind_of?(Array)
        buf = FFI::Buffer.new :pointer, arg.length + 1

        pointers = arg.map { |item| ffize_value item }
        pointers << FFI::Pointer::NULL
        buf.put_array_of_pointer 0, pointers

        buf

      elsif arg.nil?
        FFI::Pointer::NULL
      else
        arg
      end
    end

    def self.define_ffi_forwarder(*functions)
      functions.each do |id|
        GPGME.define_singleton_method(id) do |*args|
          args = args.map! { |arg| Meta.ffize_value arg }

          GPGME::Library.send id, *args
        end
      end
    end

    def self.common_gpgme_edit(context, key, ruby_callback, ruby_handle, data, receiver)
      callback = FFI::Function.new(:uint, [ :pointer, :uint, :string, :int ]) do |handle, status, args, fd|
        ruby_callback.call ruby_handle, status, args, fd

        GPGME.gpgme_err_make GPGME::GPG_ERR_SOURCE_USER_1, GPGME::GPG_ERR_NO_ERROR
      end

      context.edit_callback = callback

      receiver.call context.context_pointer, key.context_pointer, callback, FFI::Pointer::NULL,
                  data.context_pointer
    end

    def self.define_op_edit(*functions)
      functions.each do |function|
        GPGME.define_singleton_method(function) do |*args|
          common_gpgme_edit *args, GPGME::Library.method(function)
        end
      end
    end
  end
end