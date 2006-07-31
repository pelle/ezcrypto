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
  
  def test_public_key_read
    signer=EzCrypto::Signer.from_file "testsigner.pem"
    verifier=EzCrypto::Verifier.from_file "testpub.pem"
    assert verifier
    assert !verifier.cert?
    assert_equal signer.public_key.to_s, verifier.public_key.to_s
  end
  
  def test_certificate_reader
    signer=EzCrypto::Signer.from_file "testsigner.pem"
    cert=EzCrypto::Verifier.from_file "testsigner.cert"
    assert cert
    assert cert.cert?
    assert_instance_of EzCrypto::Certificate, cert
    assert_equal signer.public_key.to_s, cert.public_key.to_s
    assert_equal "/C=DK/ST=Denmark/L=Copenhagen/O=EzCrypto Test Certificate/OU=testing/CN=EzCrypto Testing/emailAddress=pelleb@gmail.com",cert.subject.to_s
    assert_equal "/C=DK/ST=Denmark/L=Copenhagen/O=EzCrypto Test Certificate/OU=testing/CN=EzCrypto Testing/emailAddress=pelleb@gmail.com",cert.issuer.to_s
    
    assert cert.serial
    assert cert.not_after
    assert cert.not_before
    assert cert.valid?
    
    assert_equal cert[:emailAddress],"pelleb@gmail.com"
    assert_equal cert[:C],"DK"
    assert_equal cert[:ST],"Denmark"
    assert_equal cert[:L],"Copenhagen"
    assert_equal cert[:OU],"testing"
    assert_equal cert[:O],"EzCrypto Test Certificate"
    assert_equal cert[:CN],"EzCrypto Testing"
    
    assert_equal cert.emailAddress,"pelleb@gmail.com"
    assert_equal cert.C,"DK"
    assert_equal cert.ST,"Denmark"
    assert_equal cert.L,"Copenhagen"
    assert_equal cert.OU,"testing"
    assert_equal cert.O,"EzCrypto Test Certificate"
    assert_equal cert.CN,"EzCrypto Testing"
    
    assert_equal cert.email,"pelleb@gmail.com"
    assert_equal cert.c,"DK"
    assert_equal cert.st,"Denmark"
    assert_equal cert.l,"Copenhagen"
    assert_equal cert.ou,"testing"
    assert_equal cert.o,"EzCrypto Test Certificate"
    assert_equal cert.cn,"EzCrypto Testing"
    
    assert_equal cert.country,"DK"
    assert_equal cert.state,"Denmark"
    assert_equal cert.locality,"Copenhagen"
    assert_equal cert.organisational_unit,"testing"
    assert_equal cert.organisation,"EzCrypto Test Certificate"
    assert_equal cert.organizational_unit,"testing"
    assert_equal cert.organization,"EzCrypto Test Certificate"
    assert_equal cert.name,"EzCrypto Testing"
    assert_equal cert.common_name,"EzCrypto Testing"
    
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