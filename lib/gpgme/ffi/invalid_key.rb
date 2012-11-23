module GPGME
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
end