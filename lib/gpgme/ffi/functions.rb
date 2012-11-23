
module GPGME

  Meta.define_ffi_forwarder :gpgme_engine_check_version,
                            :gpgme_set_engine_info,
                            :gpgme_pubkey_algo_name,
                            :gpgme_hash_algo_name,
                            :gpgme_data_get_encoding,
                            :gpgme_data_set_encoding,
                            :gpgme_set_protocol,
                            :gpgme_get_protocol,
                            :gpgme_set_armor,
                            :gpgme_get_armor,
                            :gpgme_set_textmode,
                            :gpgme_get_textmode,
                            :gpgme_get_include_certs,
                            :gpgme_set_include_certs,
                            :gpgme_set_keylist_mode,
                            :gpgme_get_keylist_mode,
                            :gpgme_get_locale,
                            :gpgme_op_keylist_start,
                            :gpgme_op_keylist_ext_start,
                            :gpgme_op_keylist_end,
                            :gpgme_op_genkey,
                            :gpgme_op_genkey_start,
                            :gpgme_op_export,
                            :gpgme_op_export_start,
                            :gpgme_op_export_ext,
                            :gpgme_op_export_ext_start,
                            :gpgme_op_export_keys,
                            :gpgme_op_export_keys_start,
                            :gpgme_op_import,
                            :gpgme_op_import_start,
                            :gpgme_op_import_keys,
                            :gpgme_op_import_keys_start,
                            :gpgme_op_delete,
                            :gpgme_op_delete_start,
                            :gpgme_op_trustlist_start,
                            :gpgme_op_trustlist_end,
                            :gpgme_op_decrypt,
                            :gpgme_op_decrypt_start,
                            :gpgme_op_verify,
                            :gpgme_op_verify_start,
                            :gpgme_op_decrypt_verify,
                            :gpgme_op_decrypt_verify_start,
                            :gpgme_signers_clear,
                            :gpgme_signers_add,
                            :gpgme_op_sign,
                            :gpgme_op_sign_start,
                            :gpgme_op_encrypt,
                            :gpgme_op_encrypt_start,
                            :gpgme_op_encrypt_sign,
                            :gpgme_op_encrypt_sign_start

  Meta.define_op_edit :gpgme_op_edit,
                      :gpgme_op_edit_start,
                      :gpgme_op_card_edit,
                      :gpgme_op_card_edit_start

  def self.gpgme_check_version(required)
    Library.gpgme_check_version_internal required, Library::Signature.offset_of(:validity)
  end

  def self.gpgme_get_engine_info(rinfo)
    engine_info = Library::EngineInfo.new
    err = Library.gpgme_get_engine_info engine_info.to_ptr

    return err if gpgme_err_code(err) != GPG_ERR_NO_ERROR

    ptr = engine_info.to_ptr
    until ptr.null?
      engine = Library::EngineInfo.new ptr

      rinfo << EngineInfo.new_from_struct(engine)

      ptr = engine[:next]
    end

    err
  end


  def self.gpgme_err_code(code)
    code & GPG_ERR_CODE_MASK
  end

  def self.gpgme_err_source(code)
    (code & GPG_ERR_SOURCE_MASK) >> GPG_ERR_SOURCE_SHIFT
  end

  def self.gpgme_err_make(source, code)
    if code == GPG_ERR_NO_ERROR
      return GPG_ERR_NO_ERROR
    end

    ((source << GPG_ERR_SOURCE_SHIFT) & GPG_ERR_SOURCE_MASK) | (code & GPG_ERR_CODE_MASK)
  end

  def self.gpgme_strerror(error)
    Library.gpgme_strerror error
  end

  def self.gpgme_data_new(rdata)
    buf = FFI::Buffer.new :pointer, 1
    err = Library.gpgme_data_new buf

    if gpgme_err_code(err) == GPG_ERR_NO_ERROR
      rdata << Data.new_from_struct(buf.read_pointer)
    end

    err
  end

  def self.gpgme_data_new_from_mem(rdata, buffer, size)
    buf = FFI::Buffer.new :pointer, 1
    err = Library.gpgme_data_new_from_mem buf, buffer, size, 1

    if gpgme_err_code(err) == GPG_ERR_NO_ERROR
      rdata << Data.new_from_struct(buf.read_pointer)
    end

    err
  end

  if RUBY_PLATFORM == "java"
    def self.gpgme_data_new_from_fd(rdata, fd)
      raise NotImplementedError, "GPGME::gpgme_data_new_from_fd cannot be used on JRuby due to NIO API limitations."
    end
  else
    def self.gpgme_data_new_from_fd(rdata, fd)
      buf = FFI::Buffer.new :pointer, 1
      err = Library.gpgme_data_new_from_fd buf, fd

      if gpgme_err_code(err) == GPG_ERR_NO_ERROR
        rdata << Data.new_from_struct(buf.read_pointer)
      end

      err
    end
  end

  def self.gpgme_data_new_from_cbs(rdata, ruby_cbs, ruby_handle)
    buf = FFI::Buffer.new :pointer, 1
    cbs = Library::Callbacks.new

    cbs[:read] = FFI::Function.new(:ssize_t, [ :pointer, :pointer, :size_t ]) do |handle, buffer, size|
      data = ruby_cbs.read ruby_handle, size

      if data.nil?
        0
      else

        buffer.write_bytes data, 0, data.length

        data.length
      end
    end

    cbs[:write] = FFI::Function.new(:ssize_t, [ :pointer, :pointer, :size_t ]) do |handle, buffer, size|
      data = buffer.read_bytes size

      ruby_cbs.write ruby_handle, data, size
    end

    cbs[:seek] = FFI::Function.new(:off_t, [ :pointer, :off_t, :int ]) do |handle, offset, whence|
      ruby_cbs.seek ruby_handle, offset, whence
    end

    cbs[:release] = FFI::Pointer::NULL

    err = Library.gpgme_data_new_from_cbs buf, cbs.to_ptr, FFI::Pointer::NULL
    if gpgme_err_code(err) == GPG_ERR_NO_ERROR
      rdata << Data.new_from_struct(buf.read_pointer, cbs)
    end

    err
  end

  def self.gpgme_data_read(data, length)
    buf = FFI::Buffer.new(:uint8, (length > 0) ? length : 1)

    bytes = Library.gpgme_data_read data.context_pointer, buf, length

    if bytes == -1
      raise "gpgme_data_read failed with error #{FFI.errno}"
    end

    return nil if bytes == 0

    buf.read_bytes bytes
  end

  def self.gpgme_data_write(data, buffer, length)
    buf = FFI::Buffer.new(:uint8, (length > 0) ? length : 1)
    if length > 0
      buf.write_bytes buffer, 0, length
    end

    bytes = Library.gpgme_data_write data.context_pointer, buf, length

    if bytes == -1
      raise "gpgme_data_write failed with error #{FFI.errno}"
    end

    bytes
  end

  def self.gpgme_data_seek(data, offset, whence)
    pos = Library.gpgme_data_seek data.context_pointer, offset, whence

    if pos == -1
      raise "gpgme_data_seek failed with error #{FFI.errno}"
    end

    pos
  end

  def self.gpgme_new(rctx)
    buf = FFI::Buffer.new :pointer, 1
    err = Library.gpgme_new buf

    if gpgme_err_code(err) == GPG_ERR_NO_ERROR
      rctx << Ctx.new_from_struct(buf.read_pointer)
    end

    err
  end

  def self.gpgme_release(ctx)
    ctx.release_pointer

    nil
  end

  def self.gpgme_set_passphrase_cb(context, ruby_callback, ruby_hook_value)
    callback = FFI::Function.new(:uint, [ :pointer, :string, :string, :int, :int ]) do |hook, uid_hint, passphrase_info, prev_was_bad, fd|
      ruby_callback.call ruby_hook_value, uid_hint, passphrase_info, prev_was_bad, fd

      gpgme_err_make GPG_ERR_SOURCE_USER_1, GPG_ERR_NO_ERROR
    end

    context.context_passphrase_callback = [ ruby_callback, ruby_hook_value, callback ]

    Library.gpgme_set_passphrase_cb context.context_pointer, callback, FFI::Pointer::NULL
  end

  def self.gpgme_get_passphrase_cb(context, rruby_callback, rruby_hook_value)
    ruby_callback, ruby_hook_value, ffi_wrapper = context.context_passphrase_callback

    rruby_callback << ruby_callback
    rruby_hook_value << ruby_hook_value

    nil
  end

  def self.gpgme_set_progress_cb(context, ruby_callback, ruby_hook_value)
    callback = FFI::Function.new(:void, [ :pointer, :string, :int, :int, :int ]) do |hook, what, type, current, total|
      ruby_callback.call ruby_hook_value, what, type, current, total
    end

    context.context_progress_callback = [ ruby_callback, ruby_hook_value, callback ]

    Library.gpgme_set_progress_cb context.context_pointer, callback, FFI::Pointer::NULL
  end

  def self.gpgme_get_progress_cb(context, rruby_callback, rruby_hook_value)
    ruby_callback, ruby_hook_value, ffi_wrapper = context.context_progress_callback

    rruby_callback << ruby_callback
    rruby_hook_value << ruby_hook_value

    nil
  end

  def self.gpgme_op_keylist_next(context, rkey)
    key = FFI::Buffer.new :pointer, 1

    ret = Library.gpgme_op_keylist_next context.context_pointer, key

    if gpgme_err_code(ret) == GPG_ERR_NO_ERROR
      rkey << Key.new_from_struct(key.read_pointer)
    end

    ret
  end

  def self.gpgme_get_key(context, fingerprint, rkey, secret)
    key = FFI::Buffer.new :pointer, 1

    ret = Library.gpgme_get_key context.context_pointer, fingerprint, key, secret

    if gpgme_err_code(ret) == GPG_ERR_NO_ERROR
      rkey << Key.new_from_struct(key.read_pointer)
    end

    ret
  end

  def self.gpgme_op_import_result(context)
    result = Library::ImportResult.new Library.gpgme_op_import_result(context.context_pointer)

    ImportResult.new_from_struct result
  end


  def self.gpgme_op_trustlist_next(context, ritem)
    buf = FFI::Buffer.new :pointer, 1

    err = Library.gpgme_op_trustlist_next context, buf

    if gpgme_err_code(err) == GPG_ERR_NO_ERROR
      ritem << TrustItem.new_from_struct(buf.read_pointer)
    end

    err
  end

  def self.gpgme_op_decrypt_result(context)
    struct = Library::DecryptResult.new Library::gpgme_op_decrypt_result(context.context_pointer)

    DecryptResult.new_from_struct struct
  end


  def self.gpgme_op_verify_result(context)
    struct = Library::VerifyResult.new Library::gpgme_op_verify_result(context.context_pointer)

    VerifyResult.new_from_struct struct
  end

  def self.gpgme_signers_enum(context, index)
    ptr = Library.gpgme_signers_enum context.context_pointer, index

    return nil if ptr.null?

    Key.new_from_struct Library::Key.new(ptr)
  end


  def self.gpgme_op_sign_result(context)
    struct = Library::SignResult.new Library::gpgme_op_verify_result(context.context_pointer)

    SignResult.new_from_struct struct
  end


  def self.gpgme_op_encrypt_result(context)
    struct = Library::EncryptResult.new Library::gpgme_op_encrypt_result(context.context_pointer)

    EncryptResult.new_from_struct struct
  end

  def self.gpgme_wait(context, rstatus, hang)
    buf = FFI::Buffer.new :uint, 1

    rctx = Library.gpgme_wait Meta.ffize_value(context), buf, hang

    return nil if rctx.null?

    rstatus << buf.read_uint

    Ctx.new_from_struct rctx
  end
end
