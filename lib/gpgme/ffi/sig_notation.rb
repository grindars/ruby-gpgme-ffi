module GPGME
  class SigNotation
    def self.new_from_struct(struct)
      instance = allocate

      instance.instance_exec do
        @name  = struct[:name]
        @value = struct[:value]
      end
    end
  end
end
