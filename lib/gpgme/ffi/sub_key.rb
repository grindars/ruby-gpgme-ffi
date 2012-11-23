module GPGME
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
end
