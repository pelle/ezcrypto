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
      case encoded
      when /-----BEGIN PUBLIC KEY-----/
        EzCrypto::Verifier.new(OpenSSL::PKey::RSA.new( encoded))
      when /-----BEGIN CERTIFICATE-----/
        EzCrypto::Certificate.new(OpenSSL::X509::Certificate.new( encoded))
      else
        raise "Unknown public key format"
      end
    end
  
    def self.from_file(filename)
      file = File.read( filename )
      decode(file)
    end
  
    def cert?
      false
    end
        
    def public_key
      @pub
    end
  
    def verify(sig,data)
      @pub.verify( OpenSSL::Digest::SHA1.new, sig, data )
    end
  end
  
  class Certificate < Verifier
    
    def initialize(cert)
      super(cert.public_key)
      @cert=cert
    end
    
    def cert?
      true
    end
    
    def subject
      @cert.subject
    end
    
    def issuer
      @cert.issuer
    end
    
    def serial
      @cert.serial
    end
    
    def cert
      @cert
    end
    
    def not_before
      @cert.not_before
    end
    
    def not_after
      @cert.not_after
    end
    
    def valid?(time=Time.now.utc)
      time.to_i>self.not_before.to_i && time.to_i<self.not_after.to_i
    end
    
    def email
      self[:emailAddress]
    end

    def country
      self[:C]
    end
    alias_method :c,:country

    def state
      self[:ST]
    end
    alias_method :st,:state
    
    def locality
      self[:L]
    end
    alias_method :l,:locality
    
    def organizational_unit
      self[:OU]
    end
    alias_method :ou,:organizational_unit
    alias_method :organisational_unit,:organizational_unit
    
    def organization
      self[:O]
    end
    alias_method :o,:organization
    alias_method :organisation,:organization
    
    def common_name
      self[:CN]
    end
    alias_method :name,:common_name
    alias_method :cn,:common_name
    
    def [](attr_key)
      unless @attributes
        @attributes={}
        subject.to_s.split(/\//).each do |field| 
          key, val = field.split(/=/,2)
          if key
            @attributes[key.to_sym]=val
          end
        end
      end
      @attributes[attr_key.to_sym]
    end
    
    def method_missing(method)
      self[method]
    end
  end
  
end