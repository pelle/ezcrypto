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
      begin
        EzCrypto::Signer.new(OpenSSL::PKey::RSA.new( encoded,password))
      rescue
        EzCrypto::Signer.new(OpenSSL::PKey::DSA.new( encoded,password))
      end
    end
  
    def self.from_file(filename,password=nil)
      file = File.read( filename )
      decode(file,password)
    end
  
    def public_key
      @priv.public_key
    end
    
    def verifier
      Verifier.new(public_key)
    end
  
    def private_key
      @priv
    end
  
    def sign(data)
      if rsa?
        @priv.sign(OpenSSL::Digest::SHA1.new,data)
      elsif dsa?
        @priv.sign(OpenSSL::Digest::DSS1.new,data)
      end
    end
  
    def rsa?
      @priv.is_a? OpenSSL::PKey::RSA
    end
    
    def dsa?
      @priv.is_a? OpenSSL::PKey::DSA
    end

  end

  class Verifier
    
    def initialize(pub)
      @pub=pub
    end
  
    def self.decode(encoded)
      case encoded
      when /-----BEGIN CERTIFICATE-----/
        EzCrypto::Certificate.new(OpenSSL::X509::Certificate.new( encoded))
      else
        EzCrypto::Verifier.new(OpenSSL::PKey::RSA.new( encoded))
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
    
    def digest
      Digest::SHA1.hexdigest(@pub.to_der)
    end

    def rsa?
      @pub.is_a? OpenSSL::PKey::RSA
    end
    
    def dsa?
      @pub.is_a? OpenSSL::PKey::DSA
    end
  
    def verify(sig,data)
      if rsa?
        @pub.verify( OpenSSL::Digest::SHA1.new, sig, data )
      elsif dsa?
        @pub.verify( OpenSSL::Digest::DSS1.new, sig, data )
      end
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
    
    def cert_digest
      Digest::SHA1.hexdigest(@cert.to_der)
    end
    
    def subject
      @subject=EzCrypto::Name.new(@cert.subject) unless @subject
      @subject
    end
    
    def issuer
      @issuer=EzCrypto::Name.new(@cert.subject) unless @issuer
      @issuer
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
    
    def extensions
      unless @extensions
        @extensions={}
        cert.extensions.each {|e| @extensions[e.oid]=e.value} if cert.extensions
      end
      @extensions
    end
    
    def method_missing(method)
      subject.send method
    end
    
  end
  
  class Name
    def initialize(name)
      @name=name
      @attributes={}
      name.to_s.split(/\//).each do |field| 
        key, val = field.split(/=/,2)
        if key
          @attributes[key.to_sym]=val
        end
      end  
    end
    
    def to_s
      @name.to_s
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
      @attributes[attr_key.to_sym]
    end
    
    def method_missing(method)
      self[method]
    end
    
  end
  
  class TrustStore
    def initialize(*paths)
      @store=OpenSSL::X509::Store.new
#      @store.set_default_path paths.shift if paths.length>0
      paths.each {|path| @store.add_path path}
    end
    
    def add(obj)
      if obj.kind_of?(EzCrypto::Certificate)
        @store.add_cert obj.cert
      elsif obj.kind_of?(OpenSSL::X509::Cert)
        @store.add_cert obj
      else 
        raise "unsupported object type"
      end
    end
    
    def verify(cert)
      if cert.kind_of?(EzCrypto::Certificate)
        @store.verify cert.cert
      elsif cert.kind_of?(OpenSSL::X509::Cert)
        @store.verify cert
      else 
        false
      end
    end
  end
end