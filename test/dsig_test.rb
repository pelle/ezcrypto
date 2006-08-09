$:.unshift(File.dirname(__FILE__) + "/../lib/")

require 'test/unit'
require 'fileutils'
require 'ezsig'
require 'base64'

class EzCryptoTest < Test::Unit::TestCase

  def setup
  end

  def _test_generate_key #very slow so not run by default
    signer=EzCrypto::Signer.generate
    assert signer.rsa?
    assert !signer.dsa?
    
    assert_signer(signer)
  end
  
  def test_from_file
    signer=EzCrypto::Signer.from_file "testsigner.pem"
    assert signer.rsa?
    assert !signer.dsa?
    assert_signer(signer)
  end

  def test_dsa_from_file
    signer=EzCrypto::Signer.from_file "dsakey.pem"
    assert signer.dsa?
    assert !signer.rsa?
    assert_signer(signer)
  end

  def test_from_password_protected_file
    signer=EzCrypto::Signer.from_file "protectedsigner.pem","secret"
    assert signer.rsa?
    assert !signer.dsa?
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
    
    sig=signer.sign "hello"
    assert sig
    assert cert.verify( sig,"hello")
    
    assert_equal "/C=DK/ST=Denmark/L=Copenhagen/O=EzCrypto Test Certificate/OU=testing/CN=EzCrypto Testing/emailAddress=pelleb@gmail.com",cert.subject.to_s
    assert_equal "/C=DK/ST=Denmark/L=Copenhagen/O=EzCrypto Test Certificate/OU=testing/CN=EzCrypto Testing/emailAddress=pelleb@gmail.com",cert.issuer.to_s
    
    assert_kind_of EzCrypto::Name,cert.issuer
    assert_kind_of EzCrypto::Name,cert.subject
    assert cert.serial
    assert cert.not_after
    assert cert.not_before
    assert cert.valid?
    
    assert_equal cert.subject[:emailAddress],"pelleb@gmail.com"
    assert_equal cert.subject[:C],"DK"
    assert_equal cert.subject[:ST],"Denmark"
    assert_equal cert.subject[:L],"Copenhagen"
    assert_equal cert.subject[:OU],"testing"
    assert_equal cert.subject[:O],"EzCrypto Test Certificate"
    assert_equal cert.subject[:CN],"EzCrypto Testing"

    assert_equal cert.subject.emailAddress,"pelleb@gmail.com"
    assert_equal cert.subject.C,"DK"
    assert_equal cert.subject.ST,"Denmark"
    assert_equal cert.subject.L,"Copenhagen"
    assert_equal cert.subject.OU,"testing"
    assert_equal cert.subject.O,"EzCrypto Test Certificate"
    assert_equal cert.subject.CN,"EzCrypto Testing"

    assert_equal cert.subject.email,"pelleb@gmail.com"
    assert_equal cert.subject.c,"DK"
    assert_equal cert.subject.st,"Denmark"
    assert_equal cert.subject.l,"Copenhagen"
    assert_equal cert.subject.ou,"testing"
    assert_equal cert.subject.o,"EzCrypto Test Certificate"
    assert_equal cert.subject.cn,"EzCrypto Testing"

    assert_equal cert.subject.country,"DK"
    assert_equal cert.subject.state,"Denmark"
    assert_equal cert.subject.locality,"Copenhagen"
    assert_equal cert.subject.organisational_unit,"testing"
    assert_equal cert.subject.organisation,"EzCrypto Test Certificate"
    assert_equal cert.subject.organizational_unit,"testing"
    assert_equal cert.subject.organization,"EzCrypto Test Certificate"
    assert_equal cert.subject.name,"EzCrypto Testing"
    assert_equal cert.subject.common_name,"EzCrypto Testing"

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

    assert_equal cert.issuer[:emailAddress],"pelleb@gmail.com"
    assert_equal cert.issuer[:C],"DK"
    assert_equal cert.issuer[:ST],"Denmark"
    assert_equal cert.issuer[:L],"Copenhagen"
    assert_equal cert.issuer[:OU],"testing"
    assert_equal cert.issuer[:O],"EzCrypto Test Certificate"
    assert_equal cert.issuer[:CN],"EzCrypto Testing"

    assert_equal cert.issuer.emailAddress,"pelleb@gmail.com"
    assert_equal cert.issuer.C,"DK"
    assert_equal cert.issuer.ST,"Denmark"
    assert_equal cert.issuer.L,"Copenhagen"
    assert_equal cert.issuer.OU,"testing"
    assert_equal cert.issuer.O,"EzCrypto Test Certificate"
    assert_equal cert.issuer.CN,"EzCrypto Testing"

    assert_equal cert.issuer.email,"pelleb@gmail.com"
    assert_equal cert.issuer.c,"DK"
    assert_equal cert.issuer.st,"Denmark"
    assert_equal cert.issuer.l,"Copenhagen"
    assert_equal cert.issuer.ou,"testing"
    assert_equal cert.issuer.o,"EzCrypto Test Certificate"
    assert_equal cert.issuer.cn,"EzCrypto Testing"
    assert_equal cert.issuer.country,"DK"
    assert_equal cert.issuer.state,"Denmark"
    assert_equal cert.issuer.locality,"Copenhagen"
    assert_equal cert.issuer.organisational_unit,"testing"
    assert_equal cert.issuer.organisation,"EzCrypto Test Certificate"
    assert_equal cert.issuer.organizational_unit,"testing"
    assert_equal cert.issuer.organization,"EzCrypto Test Certificate"
    assert_equal cert.issuer.name,"EzCrypto Testing"
    assert_equal cert.issuer.common_name,"EzCrypto Testing"
    
    ## Extensions
    
    assert cert.extensions
    
  end
  
  def test_in_memory_store
    trust=EzCrypto::TrustStore.new
    cert=EzCrypto::Verifier.from_file "testsigner.cert"
    assert !trust.verify(cert)
    trust.add cert
    assert trust.verify(cert)
    
    valicert=EzCrypto::Verifier.from_file "valicert_class2_root.crt"
    assert !trust.verify(valicert)
    starfield=EzCrypto::Verifier.from_file "sf_issuing.crt"
    assert !trust.verify(starfield)
    wideword=EzCrypto::Verifier.from_file "wideword.net.cert"
    assert !trust.verify(wideword)
    
    trust.add valicert
    assert trust.verify(valicert)
    assert trust.verify(starfield)
    assert !trust.verify(wideword)
    
    trust.add starfield
    assert trust.verify(wideword)
  end
  
  def test_disk_store
    trust=EzCrypto::TrustStore.new "store"
    valicert=EzCrypto::Verifier.from_file "valicert_class2_root.crt"
    assert trust.verify(valicert)
    starfield=EzCrypto::Verifier.from_file "sf_issuing.crt"
    assert trust.verify(starfield)
    wideword=EzCrypto::Verifier.from_file "wideword.net.cert"
    assert trust.verify(wideword)
    
    cert=EzCrypto::Verifier.from_file "testsigner.cert"
    assert !trust.verify(cert)
    trust.add cert
    assert trust.verify(cert)
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