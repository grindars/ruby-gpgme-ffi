module GPGME
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
end
