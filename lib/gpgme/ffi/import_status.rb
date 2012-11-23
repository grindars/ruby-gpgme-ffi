module GPGME
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
end
