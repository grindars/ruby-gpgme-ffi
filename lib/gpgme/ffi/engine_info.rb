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
end
