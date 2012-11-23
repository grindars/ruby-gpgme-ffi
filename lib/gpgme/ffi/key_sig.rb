module GPGME
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
end
