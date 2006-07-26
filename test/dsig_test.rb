$:.unshift(File.dirname(__FILE__) + "/../lib/")

require 'test/unit'
require 'fileutils'
require 'ezsig'
require 'base64'

class EzCryptoTest < Test::Unit::TestCase

  def setup
  end

  def test_generate_key
    signer=EzCrypto::Signer.generate
    assert_signer(signer)
  end
  
  def test_from_file
    signer=EzCrypto::Signer.from_file "testsigner.pem"
    assert_signer(signer)
  end

  def test_from_password_protected_file
    signer=EzCrypto::Signer.from_file "protectedsigner.pem","secret"
    assert_signer(signer)
  end
  
  def assert_signer(signer)
    assert signer
    assert signer.public_key
    
    sig=signer.sign "hello"
    assert sig
    assert signer.verifier
    assert signer.verifier.verify( sig,"hello")
  end
end