require 'ezcrypto'

module EzCrypto
  class Signer
  
    def initialize(priv,options = {})
      @priv=priv
    end
  
    def self.generate
      EzCrypto::Signer.new(OpenSSL::PKey::RSA.generate(2048))
    end
  
    def self.decode(encoded,password=nil)
      EzCrypto::Signer.new(OpenSSL::PKey::RSA.new( encoded,password))      
    end
  
    def self.from_file(filename,password=nil)
      file = File.read( filename )
      decode(file,password=nil)
    end
  
    def public_key
      @priv.public_key
    end
    
    def verifier
      Verifier.new(public_key)
    end
  
    def private_key
      @priv.private_key    
    end
  
    def sign(data)
      @priv.sign(OpenSSL::Digest::SHA1.new,data)
    end
  
  end

  class Verifier
    
    def initialize(pub)
      @pub=pub
    end
  
    def self.decode(encoded)
    
    end
  
    def self.from_file(file)
    
    end
  
    def public_key
      @pub
    end
  
    def verify(sig,data)
      @pub.verify( OpenSSL::Digest::SHA1.new, sig, data )
    end
  end
end