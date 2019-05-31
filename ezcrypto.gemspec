Gem::Specification.new do |s|
  s.name        = 'ezcrypto'
  s.version     = '0.7.2'
  s.date        = '2009-03-10'
  s.summary     = 'EzCrypto - Simplified Crypto Library'
  s.email       = 'pelle@stakeventures.com'
  s.homepage    = 'http://ezcrypto.rubyforge.org'
  s.description = 'EzCrypto is an easy to use wrapper around the poorly documented OpenSSL ruby library.'
  s.authors     = ['Pelle Braendgaard', 'Micah Wedemeyer']
  s.files = %w[
    rakefile
    README.rdoc
    README_ACTIVE_CRYPTO
    README_DIGITAL_SIGNATURES
    MIT-LICENSE
    CHANGELOG
    init.rb
    lib/active_crypto.rb
    lib/ezcrypto.rb
    lib/ezsig.rb
    lib/trusted.pem
    test/active_crypto_test.rb
    test/association_key_holder_test.rb
    test/database.yml
    test/digest_test.rb
    test/dsakey.pem
    test/dsapubkey.pem
    test/dsig_test.rb
    test/encrypt_test.rb
    test/ezcrypto_test.rb
    test/key_holder_test.rb
    test/protectedsigner.pem
    test/sf_intermediate.crt
    test/store
    test/test_helper.rb
    test/testchild.pem
    test/testchild.req
    test/testpub.pem
    test/testsigner.cert
    test/testsigner.pem
    test/valicert_class2_root.crt
    test/agree2.com.cert
  ]
  s.extra_rdoc_files = %w[
    CHANGELOG
    README.rdoc
    README_ACTIVE_CRYPTO
    README_DIGITAL_SIGNATURES
  ]
  s.test_files = %w[
    test/active_crypto_test.rb
    test/association_key_holder_test.rb
    test/database.yml
    test/digest_test.rb
    test/dsakey.pem
    test/dsapubkey.pem
    test/dsig_test.rb
    test/encrypt_test.rb
    test/ezcrypto_test.rb
    test/key_holder_test.rb
    test/protectedsigner.pem
    test/sf_intermediate.crt
    test/store
    test/test_helper.rb
    test/testchild.pem
    test/testchild.req
    test/testpub.pem
    test/testsigner.cert
    test/testsigner.pem
    test/valicert_class2_root.crt
    test/agree2.com.cert
  ]
end
