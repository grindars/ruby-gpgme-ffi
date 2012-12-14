Gem::Specification.new do |s|
  s.name              = 'gpgme-ffi'
  s.version           = '3.0.6'
  s.authors           = ['Daiki Ueno', 'Albert Llop', 'Sergey Gridasov']
  s.date              = '2012-12-14'
  s.email             = 'grindars@gmail.com'
  s.extensions        = ['ext/gpgme/extconf.rb']
  s.files             = Dir['{lib,ext,test,examples}/**/*']
  s.has_rdoc          = true
  s.rubyforge_project = 'ruby-gpgme'
  s.homepage          = 'http://github.com/ueno/ruby-gpgme'
  s.require_paths     = ['lib']
  s.summary           = 'FFI binding of GPGME.'
  s.description       = %q{Ruby-GPGME is a Ruby language binding of GPGME (GnuPG
Made Easy). GnuPG Made Easy (GPGME) is a library designed to make access to
GnuPG easier for applications. It provides a High-Level Crypto API for
encryption, decryption, signing, signature verification and key management.}

  s.add_dependency             "ffi",       "~> 1.2.0"
  s.add_development_dependency "mocha",     "~> 0.9.12"
  s.add_development_dependency "minitest",  "~> 2.1.0"
  if RUBY_ENGINE == "ruby"
    s.add_development_dependency "yard",      "~> 0.6.7"
    s.add_development_dependency "rcov",      "~> 0.9.9"
  end
end
