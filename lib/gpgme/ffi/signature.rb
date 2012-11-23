module GPGME
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
          notation = Library::SigNotation.new pointer

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
end
