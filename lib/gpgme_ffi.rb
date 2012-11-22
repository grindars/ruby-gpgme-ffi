require "ffi"

module GPGME
  class EngineInfo
    def self.new_from_struct(info)
      instance = allocate

      instance.instance_exec do
        @protocol    = info[:protocol]
        @file_name   = info[:file_name]
        @version     = info[:version]
        @req_version = info[:req_version]
        @home_dir    = info[:home_dir]
      end

      instance
    end
  end

  class Ctx
    attr_accessor :context_passphrase_callback
    attr_accessor :context_progress_callback

    class Pointer < ::FFI::AutoPointer
      def self.release(ptr)
        FFI.gpgme_release ptr
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

  class Data
    class Pointer < ::FFI::AutoPointer
      def self.release(ptr)
        FFI.gpgme_data_release ptr
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

  class Key
    class Pointer < FFI::AutoPointer
      def self.release(ptr)
        FFI.gpgme_key_unref ptr
      end
    end

    def self.new_from_struct(pointer)
      instance = allocate

      instance.instance_exec do
        @ptr = Pointer.new pointer

        struct = FFI::Key.new @ptr
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
          subkey = FFI::SubKey.new pointer

          @subkeys << SubKey.new_from_struct(subkey)

          pointer = subkey[:next]
        end

        @uids = []
        pointer = struct[:uids]
        until pointer.null?
          uid = FFI::UserID.new pointer

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

  class SubKey
    def self.new_from_struct(struct)
      instance = allocate

      instance.instance_exec do
        @revoked          = (struct[:flags] >> 0) & 1
        @expired          = (struct[:flags] >> 1) & 1
        @disabled         = (struct[:flags] >> 2) & 1
        @invalid          = (struct[:flags] >> 3) & 1
        @can_encrypt      = (struct[:flags] >> 4) & 1
        @can_sign         = (struct[:flags] >> 5) & 1
        @can_certify      = (struct[:flags] >> 6) & 1
        @secret           = (struct[:flags] >> 7) & 1
        @can_authenticate = (struct[:flags] >> 8) & 1
        @pubkey_algo      = struct[:pubkey_algo]
        @length           = struct[:length]
        @keyid            = struct[:keyid]
        @fpr              = struct[:fpr]
        @timestamp        = struct[:timestamp]
        @expires          = struct[:expires]
      end

      instance
    end
  end

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
          signature = FFI::KeySig

          @signatures << KeySig.new_from_struct(signature)

          pointer = signature[:next]
        end
      end

      instance
    end
  end

  class KeySig
    def self.new_from_struct(struct)
      instance = allocate

      instance.instance_exec do
        @revoked     = (struct[:flags] >> 0) & 1
        @expired     = (struct[:flags] >> 1) & 1
        @invalid     = (struct[:invalid] >> 2) & 1
        @exportable  = (struct[:exportable] >> 3) & 1
        @pubkey_algo = struct[:pubkey_algo]
        @keyid       = struct[:keyid]
        @timestamp   = struct[:timestamp]
        @expires     = struct[:expires]
      end

      instance
    end
  end

  class DecryptResult
    def self.new_from_struct(struct)
      instance = allocate

      instance.instance_exec do
        @unsupported_algorithm = struct[:unsupported_algorithm]
        @wrong_key_usage       = (struct[:flags] >> 0) & 1
      end

      instance
    end
  end

  class VerifyResult
    def self.new_from_struct(struct)
      instance = allocate

      instance.instance_exec do
        @signatures = []

        pointer = struct[:signatures]
        until pointer.null?
          signature = FFI::Signature.new pointer

          @signatures << Signature.new_from_struct(signature)

          pointer = signature[:next]
        end
      end

      instance
    end
  end

  class SignResult
    def self.new_from_struct(struct)
      instance = allocate

      instance.instance_exec do
        @invalid_signers = []

        pointer = struct[:invalid_signers]
        until pointer.null?
          key = FFI::InvalidKey.new pointer

          @invalid_signers << InvalidKey.new_from_struct(key)

          pointer = key[:next]
        end

        @signatures = []

        pointer = struct[:signatures]
        until pointer.null?
          signature = FFI::NewSignature.new pointer

          @signatures << NewSignature.new_from_struct(signature)

          pointer = key[:next]
        end
      end

      instance
    end
  end

  class EncryptResult
    def self.new_from_struct(struct)
      instance = allocate

      instance.instance_exec do
        @invalid_recipients = []

        pointer = struct[:invalid_recipients]
        until pointer.null?
          key = FFI::InvalidKey.new pointer

          @invalid_recipients << InvalidKey.new_from_struct(key)

          pointer = key[:next]
        end
      end

      instance
    end
  end

  class Signature
    def self.new_from_struct(struct)
      instance = allocate

      instance.instance_exec do
        @summary   = struct[:summary]
        @fpr       = struct[:fpr]
        @status    = struct[:status]

        @notations = []

        pointer = struct[:notations]
        until pointer.null?
          notation = FFI::SigNotation.new pointer

          @notations << SigNotation.new_from_struct(notation)

          pointer = notation[:next]
        end

        @timestamp       = struct[:timestamp]
        @exp_timestamp   = struct[:exp_timestamp]
        @wrong_key_usage = (struct[:flags] >> 0) & 1
        @pka_trust       = (struct[:flags] >> 1) & 3
        @chain_model     = (struct[:flags] >> 3) & 1
        @validity        = struct[:validity]
        @validity_reason = struct[:validity_reason]
        @pka_address     = struct[:pka_address]
      end

      instance
    end
  end

  class SigNotation
    def self.new_from_struct(struct)
      instance = allocate

      instance.instance_exec do
        @name  = struct[:name]
        @value = struct[:value]
      end
    end
  end

  class TrustItem
    class Pointer < FFI::AutoPointer
      def self.release(ptr)
        FFI.gpgme_trust_item_ref ptr
      end
    end

    def self.new_from_struct(pointer)
      instance = allocate

      instance.instance_exec do
        @ptr = Pointer.new pointer

        structure = FFI::TrustItem.new @ptr
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

  class InvalidKey
    def self.new_from_struct(struct)
      instance = allocate

      instance.instance_exec do
        @fpr    = struct[:fpr]
        @reason = struct[:reason]
      end

      instance
    end
  end

  class NewSignature
    def self.new_from_struct(struct)
      instance = allocate

      instance.instance_exec do
        @type        = struct[:type]
        @pubkey_algo = struct[:pubkey_algo]
        @hash_algo   = struct[:hash_algo]
        @sig_class   = struct[:sig_class]
        @timestamp   = struct[:timestamp]
        @fpr         = struct[:fpr]
      end

      instance
    end
  end

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
          status = FFI::ImportStatus.new pointer

          @imports << ImportStatus.new_from_struct(status)

          pointer = status[:next]
        end
      end

      instance
    end
  end

  class ImportStatus
    def self.new_from_struct(struct)
      instance = allocate

      instance.instance_exec do
        @fpr    = struct[:fpr]
        @result = struct[:result]
        @status = struct[:status]
      end

      instance
    end
  end

  def self.common_gpgme_edit(context, key, ruby_callback, ruby_handle, data, receiver)
    callback = ::FFI::Function.new(:uint, [ :pointer, :uint, :string, :int ]) do |handle, status, args, fd|
      ruby_callback.call ruby_handle, status, args, fd

      gpgme_err_make GPG_ERR_SOURCE_USER_1, GPG_ERR_NO_ERROR
    end

    context.edit_callback = callback

    receiver.call context.context_pointer, key.context_pointer, callback, ::FFI::Pointer::NULL,
                  data.context_pointer
  end

  def self.define_op_edit(*functions)
    functions.each do |function|
      define_singleton_method(function) do |*args|
        common_gpgme_edit *args, FFI.method(function)
      end
    end
  end

  def self.define_ffi_forwarder(*functions)
    functions.each do |id|
      define_singleton_method(id) do |*args|
        args = args.map! do |arg|
          if arg.respond_to?(:context_pointer)
            arg.context_pointer
          else
            arg
          end
        end

        FFI.send id, *args
      end
    end
  end

  def self.extended_pattern_buffer(pattern)
    pattern_buffer = ::FFI::Buffer.new :pointer, pattern.length + 1
    string_pointers = pattern.map { |string| ::FFI::MemoryPointer.from_string string }
    string_pointers << ::FFI::Pointer::NULL
    pattern_buffer.put_array_of_pointer 0, string_pointers

    pattern_buffer
  end

  def self.key_buffer(keys)
    return ::FFI::Pointer::NULL if keys.nil?

    buf = ::FFI::Buffer.new :pointer, keys.length + 1

    pointers = keys.map(&:context_pointer)
    pointers << ::FFI::Pointer::NULL

    buf.write_array_of_pointer pointers

    buf
  end

  def self.gpgme_check_version(required)
    FFI.gpgme_check_version_internal required, FFI::Signature.offset_of(:validity)
  end

  define_ffi_forwarder :gpgme_engine_check_version

  def self.gpgme_get_engine_info(rinfo)
    engine_info = FFI::EngineInfo.new
    err = FFI.gpgme_get_engine_info engine_info.to_ptr

    return err if gpgme_err_code(err) != GPG_ERR_NO_ERROR

    ptr = engine_info.to_ptr
    until ptr.null?
      engine = FFI::EngineInfo.new ptr

      rinfo << EngineInfo.new_from_struct(engine)

      ptr = engine[:next]
    end

    err
  end

  define_ffi_forwarder :gpgme_set_engine_info,
                       :gpgme_pubkey_algo_name,
                       :gpgme_hash_algo_name

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
    FFI.gpgme_strerror error
  end

  def self.gpgme_data_new(rdata)
    buf = ::FFI::Buffer.new :pointer, 1
    err = FFI.gpgme_data_new buf

    if gpgme_err_code(err) == GPG_ERR_NO_ERROR
      rdata << Data.new_from_struct(buf.read_pointer)
    end

    err
  end

  def self.gpgme_data_new_from_mem(rdata, buffer, size)
    buf = ::FFI::Buffer.new :pointer, 1
    err = FFI.gpgme_data_new_from_mem buf, buffer, size, 1

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
      buf = ::FFI::Buffer.new :pointer, 1
      err = FFI.gpgme_data_new_from_fd buf, fd

      if gpgme_err_code(err) == GPG_ERR_NO_ERROR
        rdata << Data.new_from_struct(buf.read_pointer)
      end

      err
    end
  end

  def self.gpgme_data_new_from_cbs(rdata, ruby_cbs, ruby_handle)
    buf = ::FFI::Buffer.new :pointer, 1
    cbs = FFI::Callbacks.new

    cbs[:read] = ::FFI::Function.new(:ssize_t, [ :pointer, :pointer, :size_t ]) do |handle, buffer, size|
      data = ruby_cbs.read ruby_handle, size

      if data.nil?
        0
      else

        buffer.write_bytes data, 0, data.length

        data.length
      end
    end

    cbs[:write] = ::FFI::Function.new(:ssize_t, [ :pointer, :pointer, :size_t ]) do |handle, buffer, size|
      data = buffer.read_bytes size

      ruby_cbs.write ruby_handle, data, size
    end

    cbs[:seek] = ::FFI::Function.new(:off_t, [ :pointer, :off_t, :int ]) do |handle, offset, whence|
      ruby_cbs.seek ruby_handle, offset, whence
    end

    cbs[:release] = ::FFI::Pointer::NULL

    err = FFI.gpgme_data_new_from_cbs buf, cbs.to_ptr, ::FFI::Pointer::NULL
    if gpgme_err_code(err) == GPG_ERR_NO_ERROR
      rdata << Data.new_from_struct(buf.read_pointer, cbs)
    end

    err
  end

  def self.gpgme_data_read(data, length)
    buf = ::FFI::Buffer.new(:uint8, (length > 0) ? length : 1)

    bytes = FFI.gpgme_data_read data.context_pointer, buf, length

    if bytes == -1
      raise "gpgme_data_read failed with error #{::FFI.errno}"
    end

    return nil if bytes == 0

    buf.read_bytes bytes
  end

  def self.gpgme_data_write(data, buffer, length)
    buf = ::FFI::Buffer.new(:uint8, (length > 0) ? length : 1)
    if length > 0
      buf.write_bytes buffer, 0, length
    end

    bytes = FFI.gpgme_data_write data.context_pointer, buf, length

    if bytes == -1
      raise "gpgme_data_write failed with error #{::FFI.errno}"
    end

    bytes
  end

  def self.gpgme_data_seek(data, offset, whence)
    pos = FFI.gpgme_data_seek data.context_pointer, offset, whence

    if pos == -1
      raise "gpgme_data_seek failed with error #{FFI.errno}"
    end

    pos
  end

  define_ffi_forwarder :gpgme_data_get_encoding,
                       :gpgme_data_set_encoding

  def self.gpgme_new(rctx)
    buf = ::FFI::Buffer.new :pointer, 1
    err = FFI.gpgme_new buf

    if gpgme_err_code(err) == GPG_ERR_NO_ERROR
      rctx << Ctx.new_from_struct(buf.read_pointer)
    end

    err
  end

  def self.gpgme_release(ctx)
    ctx.release_pointer

    nil
  end

  define_ffi_forwarder :gpgme_set_protocol,
                       :gpgme_get_protocol,
                       :gpgme_set_armor,
                       :gpgme_get_armor,
                       :gpgme_set_textmode,
                       :gpgme_get_textmode,
                       :gpgme_get_include_certs,
                       :gpgme_set_include_certs,
                       :gpgme_set_keylist_mode,
                       :gpgme_get_keylist_mode

  def self.gpgme_set_passphrase_cb(context, ruby_callback, ruby_hook_value)
    callback = ::FFI::Function.new(:uint, [ :pointer, :string, :string, :int, :int ]) do |hook, uid_hint, passphrase_info, prev_was_bad, fd|
      ruby_callback.call ruby_hook_value, uid_hint, passphrase_info, prev_was_bad, fd

      gpgme_err_make GPG_ERR_SOURCE_USER_1, GPG_ERR_NO_ERROR
    end

    context.context_passphrase_callback = [ ruby_callback, ruby_hook_value, callback ]

    FFI.gpgme_set_passphrase_cb context.context_pointer, callback, ::FFI::Pointer::NULL
  end

  def self.gpgme_get_passphrase_cb(context, rruby_callback, rruby_hook_value)
    ruby_callback, ruby_hook_value, ffi_wrapper = context.context_passphrase_callback

    rruby_callback << ruby_callback
    rruby_hook_value << ruby_hook_value

    nil
  end

  def self.gpgme_set_progress_cb(context, ruby_callback, ruby_hook_value)
    callback = ::FFI::Function.new(:void, [ :pointer, :string, :int, :int, :int ]) do |hook, what, type, current, total|
      ruby_callback.call ruby_hook_value, what, type, current, total
    end

    context.context_progress_callback = [ ruby_callback, ruby_hook_value, callback ]

    FFI.gpgme_set_progress_cb context.context_pointer, callback, ::FFI::Pointer::NULL
  end

  def self.gpgme_get_progress_cb(context, rruby_callback, rruby_hook_value)
    ruby_callback, ruby_hook_value, ffi_wrapper = context.context_progress_callback

    rruby_callback << ruby_callback
    rruby_hook_value << ruby_hook_value

    nil
  end

  define_ffi_forwarder :gpgme_get_locale,
                       :gpgme_op_keylist_start

  def self.gpgme_op_keylist_ext_start(context, pattern, secret_only)
    FFI.gpgme_op_keylist_ext_start context.context_pointer, extended_pattern_buffer(pattern), secret_only
  end

  def self.gpgme_op_keylist_next(context, rkey)
    key = ::FFI::Buffer.new :pointer, 1

    ret = FFI.gpgme_op_keylist_next context.context_pointer, key

    if gpgme_err_code(ret) == GPG_ERR_NO_ERROR
      rkey << Key.new_from_struct(key.read_pointer)
    end

    ret
  end

  define_ffi_forwarder :gpgme_op_keylist_end

  def self.gpgme_get_key(context, fingerprint, rkey, secret)
    key = ::FFI::Buffer.new :pointer, 1

    ret = FFI.gpgme_get_key context.context_pointer, fingerprint, key, secret

    if gpgme_err_code(ret) == GPG_ERR_NO_ERROR
      rkey << Key.new_from_struct(key.read_pointer)
    end

    ret
  end

  def self.gpgme_op_genkey(context, params, pubkey, seckey)
    if pubkey.nil?
      pubkey_ptr = ::FFI::Pointer::NULL
    else
      pubkey_ptr = pubkey.context_pointer
    end

    if seckey.nil?
      seckey_ptr = ::FFI::Pointer::NULL
    else
      seckey_ptr = seckey.context_pointer
    end

    FFI.gpgme_op_genkey context.context_pointer, params, pubkey_ptr, seckey_ptr
  end

  def self.gpgme_op_genkey_start(context, params, pubkey, seckey)
    if pubkey.nil?
      pubkey_ptr = ::FFI::Pointer::NULL
    else
      pubkey_ptr = pubkey.context_pointer
    end

    if seckey.nil?
      seckey_ptr = ::FFI::Pointer::NULL
    else
      seckey_ptr = seckey.context_pointer
    end

    FFI.gpgme_op_genkey_start context.context_pointer, params, pubkey_ptr, seckey_ptr
  end

  define_ffi_forwarder :gpgme_op_export,
                       :gpgme_op_export_start

  def self.gpgme_op_export_ext(context, pattern, mode, keydata)
    FFI.gpgme_op_export_ext context.context_pointer, extended_pattern_buffer(pattern), mode, keydata.context_pointer
  end

  def self.gpgme_op_export_ext_start(context, pattern, mode, keydata)
    FFI.gpgme_op_export_ext_start context.context_pointer, extended_pattern_buffer(pattern), mode, keydata.context_pointer
  end

  def self.gpgme_op_export_keys(context, keys, mode, keydata)
    FFI.gpgme_op_export_keys context.context_pointer key_buffer(keys), mode, keydata.context_pointer
  end

  def self.gpgme_op_export_keys_start(context, keys, mode, keydata)
    FFI.gpgme_op_export_keys_start context.context_pointer, key_buffer(keys), mode, keydata.context_pointer
  end

  define_ffi_forwarder :gpgme_op_import,
                       :gpgme_op_import_start

  def self.gpgme_op_import_keys(context, keys)
    FFI.gpgme_op_import_keys context.context_pointer, key_buffer(keys)
  end

  def self.gpgme_op_import_keys_start(context, keys)
    FFI.gpgme_op_import_keys_start context.context_pointer, key_buffer(keys)
  end

  def self.gpgme_op_import_result(context)
    result = FFI::ImportResult.new FFI.gpgme_op_import_result(context.context_pointer)

    ImportResult.new_from_struct result
  end

  define_ffi_forwarder :gpgme_op_delete,
                       :gpgme_op_delete_start

  define_op_edit :gpgme_op_edit,
                 :gpgme_op_edit_start,
                 :gpgme_op_card_edit,
                 :gpgme_op_card_edit_start


  define_ffi_forwarder :gpgme_op_trustlist_start

  def self.gpgme_op_trustlist_next(context, ritem)
    buf = ::FFI::Buffer.new :pointer, 1

    err = FFI.gpgme_op_trustlist_next context, buf

    if gpgme_err_code(err) == GPG_ERR_NO_ERROR
      ritem << TrustItem.new_from_struct(buf.read_pointer)
    end

    err
  end

  define_ffi_forwarder :gpgme_op_trustlist_end,
                       :gpgme_op_decrypt,
                       :gpgme_op_decrypt_start

  def self.gpgme_op_decrypt_result(context)
    struct = FFI::DecryptResult.new FFI::gpgme_op_decrypt_result(context.context_pointer)

    DecryptResult.new_from_struct struct
  end

  define_ffi_forwarder :gpgme_op_verify,
                       :gpgme_op_verify_start

  def self.gpgme_op_verify_result(context)
    struct = FFI::VerifyResult.new FFI::gpgme_op_verify_result(context.context_pointer)

    VerifyResult.new_from_struct struct
  end

  define_ffi_forwarder :gpgme_op_decrypt_verify,
                       :gpgme_op_decrypt_verify_start,
                       :gpgme_signers_clear,
                       :gpgme_signers_add

  def self.gpgme_signers_enum(context, index)
    ptr = FFI.gpgme_signers_enum context.context_pointer, index

    return nil if ptr.null?

    Key.new_from_struct FFI::Key.new(ptr)
  end

  define_ffi_forwarder :gpgme_op_sign,
                       :gpgme_op_sign_start

  def self.gpgme_op_sign_result(context)
    struct = FFI::SignResult.new FFI::gpgme_op_verify_result(context.context_pointer)

    SignResult.new_from_struct struct
  end

  def self.gpgme_op_encrypt(context, recp, flags, plain, cipher)
    FFI.gpgme_op_encrypt context.context_pointer, key_buffer(recp), flags, plain.context_pointer, cipher.context_pointer
  end

  def self.gpgme_op_encrypt_start(context, recp, flags, plain, cipher)
    FFI.gpgme_op_encrypt_start context.context_pointer, key_buffer(recp), flags, plain.context_pointer, cipher.context_pointer
  end

  def self.gpgme_op_encrypt_sign(context, recp, flags, plain, cipher)
    FFI.gpgme_op_encrypt_sign context.context_pointer, key_buffer(recp), flags, plain.context_pointer, cipher.context_pointer
  end

  def self.gpgme_op_encrypt_sign_start(context, recp, flags, plain, cipher)
    FFI.gpgme_op_encrypt_sign_start context.context_pointer, key_buffer(recp), flags, plain.context_pointer, cipher.context_pointer
  end

  def self.gpgme_op_encrypt_result(context)
    struct = FFI::EncryptResult.new FFI::gpgme_op_encrypt_result(context.context_pointer)

    EncryptResult.new_from_struct struct
  end

end

module GPGME::FFI
  extend FFI::Library

  ffi_lib 'libgpgme.so.11'

  class SigNotation < FFI::Struct
    layout :next,      :pointer,
           :name,      :string,
           :value,     :string,
           :name_len,  :int,
           :value_len, :int,
           :flags,     :uint,
           # packed: human_readable, critical, _unused
           :bits,      :uint
  end

  class Signature < FFI::Struct
    layout :next,            :pointer,
           :summary,         :int,
           :fpr,             :string,
           :status,          :uint,
           :notations,       :pointer,
           :timestamp,       :ulong,
           :exp_timestamp,   :ulong,
           # packed: wrong_key_usage, pka_trust, chain_model, _unused
           :flags,           :uint,
           :validity,        :uint,
           :validity_reason, :uint,
           :pubkey_algo,     :uint,
           :hash_algo,       :uint,
           :pka_address,     :string
  end

  class EngineInfo < FFI::Struct
    layout :next,            :pointer,
           :protocol,        :uint,
           :file_name,       :string,
           :version,         :string,
           :req_version,     :string,
           :home_dir,        :string
  end

  class Callbacks < FFI::Struct
    layout :read,    :pointer,
           :write,   :pointer,
           :seek,    :pointer,
           :release, :pointer
  end

  class ImportStatus < FFI::Struct
    layout :next,   :pointer,
           :fpr,    :string,
           :result, :uint,
           :status, :uint
  end

  class ImportResult < FFI::Struct
    layout :considered,       :int,
           :no_user_id,       :int,
           :imported,         :int,
           :imported_rsa,     :int,
           :unchanged,        :int,
           :new_user_ids,     :int,
           :new_sub_keys,     :int,
           :new_signatures,   :int,
           :new_revocations,  :int,
           :secret_read,      :int,
           :secret_imported,  :int,
           :secret_unchanged, :int,
           :skipped_new_keys, :int,
           :not_imported,     :int,
           :imports,          :pointer
  end

  class TrustItem < FFI::Struct
    layout :_refs,        :uint,
           :keyid,        :string,
           :_keyid,       [ :uint8, 16 + 1 ],
           :type,         :int,
           :level,        :int,
           :owner_trust,  :string,
           :_owner_trust, [ :uint8, 2 ],
           :validity,     :string,
           :_validity,    [ :uint8, 2 ],
           :name,         :string
  end

  class Key < FFI::Struct
    layout :_refs,         :uint,
           # packed: revoked, expired, disabled, invalid, can_encrypt, can_sign, can_certify,
           # secret, can_authenticate, is_qualified, _unused
           :flags,         :uint,
           :protocol,      :uint,
           :issuer_serial, :string,
           :issuer_name,   :string,
           :chain_id,      :string,
           :owner_trust,   :uint,
           :subkeys,       :pointer,
           :uids,          :pointer,
           :_last_subkey,  :pointer,
           :_last_uid,     :pointer,
           :keylist_mode,  :uint
  end

  class SubKey < FFI::Struct
    layout :next,        :pointer,
           # packed, see above + is_cardkey
           :flags,       :uint,
           :pubkey_algo, :uint,
           :length,      :uint,
           :keyid,       :string,
           :_keyid,      [ :uint8, 16 + 1],
           :fpr,         :string,
           :timestamp,   :long,
           :expires,     :long,
           :card_number, :string
  end

  class UserID < FFI::Struct
    layout :next,         :pointer,
           # packed: revoked, invalid
           :flags,        :uint,
           :validity,     :uint,
           :uid,          :string,
           :name,         :string,
           :email,        :string,
           :comment,      :string,
           :signatures,   :pointer,
           :_last_keysig, :pointer
  end

  class KeySig < FFI::Struct
    layout :next,            :pointer,
           # packed: revoked, expired, invalid, exportable
           :flags,           :uint,
           :pubkey_algo,     :uint,
           :keyid,           :string,
           :_keyid,          [ :uint8, 16 + 1 ],
           :timestamp,       :long,
           :expires,         :long,
           :status,          :uint,
           :_obsolete_class, :uint,
           :uid,             :string,
           :name,            :string,
           :email,           :string,
           :comment,         :string,
           :sig_class,       :uint,
           :notations,       :pointer,
           :_last_notation,  :pointer
  end

  class DecryptResult < FFI::Struct
    layout :unsupported_algorithm, :string,
           # packed: wrong_key_usage
           :flags,                 :uint,
           :recipients,            :pointer,
           :file_name,             :string
  end

  class VerifyResult < FFI::Struct
    layout :signatures, :pointer,
           :file_name,  :string
  end

  class SignResult < FFI::Struct
    layout :invalid_signers, :pointer,
           :signatures,      :pointer
  end

  class InvalidKey < FFI::Struct
    layout :next,   :pointer,
           :fpr,    :string,
           :reason, :uint
  end

  class EncryptResult < FFI::Struct
    layout :invalid_recipients, :pointer
  end

  class NewSignature < FFI::Struct
    layout :next,              :pointer,
           :type,              :uint,
           :pubkey_algo,       :uint,
           :hash_algo,         :uint,
           :_obsolete_class,   :ulong,
           :timestamp,         :long,
           :fpr,               :string,
           :_obsolete_class_2, :uint,
           :sig_class,         :uint
  end

  attach_function :gpgme_check_version_internal,  [ :string, :size_t ], :string
  attach_function :gpgme_engine_check_version,    [ :uint ], :uint
  attach_function :gpgme_get_engine_info,         [ :pointer ], :uint
  attach_function :gpgme_set_engine_info,         [ :uint, :string, :string ], :uint
  attach_function :gpgme_pubkey_algo_name,        [ :uint ], :string
  attach_function :gpgme_hash_algo_name,          [ :uint ], :string
  attach_function :gpgme_strerror,                [ :uint ], :string
  attach_function :gpgme_data_new,                [ :pointer ], :uint
  attach_function :gpgme_data_new_from_mem,       [ :pointer, :string, :size_t, :int ], :uint
  attach_function :gpgme_data_new_from_fd,        [ :pointer, :int ], :uint
  attach_function :gpgme_data_new_from_cbs,       [ :pointer, :pointer, :pointer ], :uint
  attach_function :gpgme_data_release,            [ :pointer ], :void
  attach_function :gpgme_data_read,               [ :pointer, :buffer_out, :size_t ], :ssize_t
  attach_function :gpgme_data_write,              [ :pointer, :buffer_in, :size_t ], :ssize_t
  attach_function :gpgme_data_seek,               [ :pointer, :off_t, :int ], :off_t
  attach_function :gpgme_data_get_encoding,       [ :pointer ], :uint
  attach_function :gpgme_data_set_encoding,       [ :pointer, :uint ], :uint
  attach_function :gpgme_new,                     [ :pointer ], :uint
  attach_function :gpgme_release,                 [ :pointer ], :void
  attach_function :gpgme_set_protocol,            [ :pointer, :uint ], :uint
  attach_function :gpgme_get_protocol,            [ :pointer ], :uint
  attach_function :gpgme_set_armor,               [ :pointer, :uint ], :void
  attach_function :gpgme_get_armor,               [ :pointer ], :uint
  attach_function :gpgme_set_textmode,            [ :pointer, :uint ], :void
  attach_function :gpgme_get_textmode,            [ :pointer ], :uint
  attach_function :gpgme_set_include_certs,       [ :pointer, :uint ], :void
  attach_function :gpgme_get_include_certs,       [ :pointer ], :uint
  attach_function :gpgme_set_keylist_mode,        [ :pointer, :uint ], :uint
  attach_function :gpgme_get_keylist_mode,        [ :pointer ], :uint
  attach_function :gpgme_set_passphrase_cb,       [ :pointer, :pointer, :pointer ], :void
  attach_function :gpgme_get_passphrase_cb,       [ :pointer, :pointer, :pointer ], :void
  attach_function :gpgme_set_progress_cb,         [ :pointer, :pointer, :pointer ], :void
  attach_function :gpgme_get_progress_cb,         [ :pointer, :pointer, :pointer ], :void
  attach_function :gpgme_set_locale,              [ :pointer, :int, :string ], :uint
  attach_function :gpgme_op_keylist_start,        [ :pointer, :string, :int ], :uint
  attach_function :gpgme_op_keylist_ext_start,    [ :pointer, :buffer_in, :int, :int ], :uint
  attach_function :gpgme_op_keylist_next,         [ :pointer, :buffer_out ], :uint
  attach_function :gpgme_op_keylist_end,          [ :pointer ], :uint
  attach_function :gpgme_get_key,                 [ :pointer, :string, :buffer_out, :int ], :uint
  attach_function :gpgme_key_ref,                 [ :pointer ], :void
  attach_function :gpgme_key_unref,               [ :pointer ], :void
  attach_function :gpgme_op_genkey,               [ :pointer, :string, :pointer, :pointer ], :uint
  attach_function :gpgme_op_genkey_start,         [ :pointer, :string, :pointer, :pointer ], :uint
  attach_function :gpgme_op_export,               [ :pointer, :string, :int, :pointer ], :uint
  attach_function :gpgme_op_export_start,         [ :pointer, :string, :int, :pointer ], :uint
  attach_function :gpgme_op_export_ext,           [  :pointer, :buffer_in, :int, :pointer ], :uint
  attach_function :gpgme_op_export_ext_start,     [ :pointer, :buffer_in, :int, :pointer ], :uint
  attach_function :gpgme_op_export_keys,          [ :pointer, :buffer_in, :int, :pointer ], :uint
  attach_function :gpgme_op_export_keys_start,    [ :pointer, :buffer_in, :int, :pointer ], :uint
  attach_function :gpgme_op_import,               [ :pointer, :pointer ], :uint
  attach_function :gpgme_op_import_start,         [ :pointer, :pointer ], :uint
  attach_function :gpgme_op_import_keys,          [ :pointer, :buffer_in ], :uint
  attach_function :gpgme_op_import_keys_start,    [ :pointer, :buffer_in ], :uint
  attach_function :gpgme_op_import_result,        [ :pointer ], :pointer
  attach_function :gpgme_op_delete,               [ :pointer, :pointer, :int ], :uint
  attach_function :gpgme_op_delete_start,         [ :pointer, :pointer, :int ], :uint
  attach_function :gpgme_op_edit,                 [ :pointer, :pointer, :pointer, :pointer, :pointer ], :uint
  attach_function :gpgme_op_edit_start,           [ :pointer, :pointer, :pointer, :pointer, :pointer ], :uint
  attach_function :gpgme_op_card_edit,            [ :pointer, :pointer, :pointer, :pointer, :pointer ], :uint
  attach_function :gpgme_op_card_edit_start,      [ :pointer, :pointer, :pointer, :pointer, :pointer ], :uint
  attach_function :gpgme_op_trustlist_start,      [ :pointer, :string, :int ], :uint
  attach_function :gpgme_op_trustlist_next,       [ :pointer, :buffer_out ], :uint
  attach_function :gpgme_op_trustlist_end,        [ :pointer ], :uint
  attach_function :gpgme_trust_item_ref,          [ :pointer ], :void
  attach_function :gpgme_trust_item_unref,        [ :pointer ], :void
  attach_function :gpgme_op_decrypt,              [ :pointer, :pointer, :pointer ], :uint
  attach_function :gpgme_op_decrypt_start,        [ :pointer, :pointer, :pointer ], :uint
  attach_function :gpgme_op_decrypt_result,       [ :pointer ], :pointer
  attach_function :gpgme_op_verify,               [ :pointer, :pointer, :pointer, :pointer ], :uint
  attach_function :gpgme_op_verify_start,         [ :pointer, :pointer, :pointer, :pointer ], :uint
  attach_function :gpgme_op_verify_result,        [ :pointer ], :pointer
  attach_function :gpgme_op_decrypt_verify,       [ :pointer, :pointer, :pointer ], :uint
  attach_function :gpgme_op_decrypt_verify_start, [ :pointer, :pointer, :pointer ], :uint
  attach_function :gpgme_signers_clear,           [ :pointer ], :void
  attach_function :gpgme_signers_add,             [ :pointer, :pointer ], :uint
  attach_function :gpgme_signers_enum,            [ :pointer, :int ], :pointer
  attach_function :gpgme_op_sign,                 [ :pointer, :pointer, :pointer, :uint ], :uint
  attach_function :gpgme_op_sign_start,           [ :pointer, :pointer, :pointer, :uint ], :uint
  attach_function :gpgme_op_sign_result,          [ :pointer ], :pointer
  attach_function :gpgme_op_encrypt,              [ :pointer, :buffer_in, :uint, :pointer, :pointer ], :uint
  attach_function :gpgme_op_encrypt_start,        [ :pointer, :buffer_in, :uint, :pointer, :pointer ], :uint
  attach_function :gpgme_op_encrypt_sign,         [ :pointer, :buffer_in, :uint, :pointer, :pointer ], :uint
  attach_function :gpgme_op_encrypt_sign_start,   [ :pointer, :buffer_in, :uint, :pointer, :pointer ], :uint
  attach_function :gpgme_op_encrypt_result,       [ :pointer ], :pointer
end
