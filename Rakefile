require 'bundler'
Bundler::GemHelper.install_tasks

require 'rake/testtask'
if RUBY_ENGINE == 'ruby'
    require 'rcov/rcovtask'
    require 'yard'
end

desc "Re-compile the extensions"
task :compile do
  FileUtils.rm_rf('tmp') if File.directory?('tmp')
  mkdir 'tmp'

  Dir.chdir('tmp') do
    system "ruby #{File.dirname(__FILE__)}/ext/gpgme/extconf.rb"
    system "make all install"
  end
end

task :default => [:compile, :test]

Rake::TestTask.new(:test) do |t|
  t.libs << 'test'
  t.pattern = "test/**/*_test.rb"
  t.verbose = true
end
Rake::Task['test'].comment = "Run all tests"

if RUBY_ENGINE == 'ruby'
    YARD::Rake::YardocTask.new

    Rcov::RcovTask.new do |t|
    t.libs << 'test'
    t.pattern = "test/**/*_test.rb"
    t.verbose = true
    t.rcov_opts = ["-x gems"]
    end
end

