require 'ffi'

module GPGME::Library
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

  attach_function :gpgme_check_version_internal,  [ :buffer_in, :size_t ], :string
  attach_function :gpgme_engine_check_version,    [ :uint ], :uint
  attach_function :gpgme_get_engine_info,         [ :pointer ], :uint
  attach_function :gpgme_set_engine_info,         [ :uint, :buffer_in, :buffer_in ], :uint
  attach_function :gpgme_pubkey_algo_name,        [ :uint ], :string
  attach_function :gpgme_hash_algo_name,          [ :uint ], :string
  attach_function :gpgme_strerror,                [ :uint ], :string
  attach_function :gpgme_data_new,                [ :pointer ], :uint
  attach_function :gpgme_data_new_from_mem,       [ :pointer, :buffer_in, :size_t, :int ], :uint
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
  attach_function :gpgme_set_locale,              [ :pointer, :int, :buffer_in ], :uint
  attach_function :gpgme_op_keylist_start,        [ :pointer, :buffer_in, :int ], :uint
  attach_function :gpgme_op_keylist_ext_start,    [ :pointer, :buffer_in, :int, :int ], :uint
  attach_function :gpgme_op_keylist_next,         [ :pointer, :buffer_out ], :uint
  attach_function :gpgme_op_keylist_end,          [ :pointer ], :uint
  attach_function :gpgme_get_key,                 [ :pointer, :buffer_in, :buffer_out, :int ], :uint
  attach_function :gpgme_key_ref,                 [ :pointer ], :void
  attach_function :gpgme_key_unref,               [ :pointer ], :void
  attach_function :gpgme_op_genkey,               [ :pointer, :buffer_in, :pointer, :pointer ], :uint
  attach_function :gpgme_op_genkey_start,         [ :pointer, :buffer_in, :pointer, :pointer ], :uint
  attach_function :gpgme_op_export,               [ :pointer, :buffer_in, :int, :pointer ], :uint
  attach_function :gpgme_op_export_start,         [ :pointer, :buffer_in, :int, :pointer ], :uint
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
  attach_function :gpgme_op_trustlist_start,      [ :pointer, :buffer_in, :int ], :uint
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
  attach_function :gpgme_wait,                    [ :pointer, :buffer_out, :int ], :pointer
end
