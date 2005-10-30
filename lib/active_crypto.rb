require "ezCrypto"
module ActiveRecord # :nodoc:
  module Crypto  #:nodoc:
    
    def self.append_features(base)  #:nodoc:
      super
      base.extend(ClassMethods)
    end
    
=begin rdoc

Usage is very simple. You will generally only need the two class methods listed here in your ActiveRecord class model.

== License

ActiveCrypto and EzCrypto are released under the MIT license.


== Support

To contact the author, send mail to pelleb@gmail.com

Also see my blogs at:
http://stakeventures.com and
http://neubia.com

This project was based on code used in my project StakeItOut, where you can securely share web services with your partners.
https://stakeitout.com

(C) 2005 Pelle Braendgaard

=end
    module ClassMethods
      @@session_keys={}

=begin rdoc
Turn encryption on for this record. List all encrypted attributes

  class Document < ActiveRecord::Base
		encrypt :title,:body
	end
	
Include optional option :key, to specify an external KeyHolder, which holds the key used for encrypting and decrypting:

  class Document < ActiveRecord::Base
  	belongs_to :user
  	encrypt :title,:body,:key=>:user
  end
	
=end
      def encrypt(*attributes)        
        	include ActiveRecord::Crypto::Encrypted
        	alias_method :orig_write_attribute, :write_attribute
        	alias_method :write_attribute,:write_encrypted_attribute
          options=attributes.last.is_a?(Hash) ? attributes.pop : {}
          if options and options[:key]
    				module_eval <<-"end;"				 
    					def session_key
    						(send :#{options[:key]} ).send :session_key
    					end	 
    				end;
                
          end
  			self.encrypted_attributes=attributes
  			for enc in attributes
            
  				module_eval <<-"end;"
  					def #{enc.to_s}
  						_decrypt(read_attribute("#{enc.to_s}"))
  					end	 
  				end;
			  end
      end   
		
=begin rdoc
Creates support in this class for holding a key. Adds the following methods:

* enter_password(password,salt="onetwothree")
* set_session_key(key)
* session_key

Use it as follows:

  class User < ActiveRecord::Base
  	has_many :documents
  	keyholder
  end

=end        
      def keyholder()
      	include ActiveRecord::Crypto::KeyHolder          
      end

=begin rdoc
Clears the session_key array. Generally this is handled automatically as a filter in ActionController. Only use these if you need to
do something out of the ordinary.
=end
      def clear_session_keys() #:nodoc:
        @@session_keys.clear
      end 
      
=begin rdoc
Sets the session_keys array. Only use these if you need to
do something out of the ordinary, as it is handled
=end
      def session_keys=(keys) #:nodoc:
        @@session_keys=keys
      end
      
      def session_keys() #:nodoc:
        @@session_keys
      end
    end

=begin rdoc
This module handles all standard key management features.
=end
    module KeyHolder   

=begin rdoc
Creates a key for object based on given password and an optional salt.
=end
      def enter_password(password,salt="onetwothree")
        set_session_key(EzCrypto::Key.with_password password, salt)
      end

=begin rdoc
Sets a session key for the object. This should be a EzCrypto::Key instance.
=end
      def set_session_key(key)    
        Base.session_keys[session_key_id]=key
      end      

=begin rdoc
Returns the session_key
=end
      def session_key
        Base.session_keys[session_key_id]
      end
      
      private
      
      def session_key_id
          "#{self.class.to_s}:#{id}"
      end      
    end

    module Encrypted    #:nodoc:
      include ActiveRecord::Crypto::KeyHolder
      def self.append_features(base)  #:nodoc:
        super
				base.module_eval <<-"end;"				 
         @@encrypted_attributes=[]
          def encrypted_attributes
            @@encrypted_attributes
          end
          
          def #{base.to_s}.encrypted_attributes=(attrs)
            @@encrypted_attributes=attrs
          end
        end;
      end

      def write_encrypted_attribute(name,value)
        if encrypted_attributes.include?(name.to_sym)
            orig_write_attribute(name,_encrypt(value))
        else
   		    orig_write_attribute(name,value)
  	    end
      end
    end
    
    private
    
    def _decrypt(data)
      if session_key.nil?
        raise MissingKeyError
      else
        session_key.decrypt(data)
      end
    end
    
    def _encrypt(data)
      if session_key.nil?
        raise MissingKeyError
      else 
        session_key.encrypt(data)
      end
    end
               
  end
  
  class Base # :nodoc:
    include ActiveRecord::Crypto
  end
end

module ActionController # :nodoc:
=begin rdoc
This includes some basic support in the ActionController for handling session keys. It creates two filters one before the action and one after.
These do the following:
  
If the users session already has a 'session_keys' value it loads it into the ActiveRecord::Base.session_keys class field. If not it 
clears any existing session_keys.

Leaving the action it stores any session_keys in the corresponding session variable.

These filters are automatically enabled. You do not have to do anything.
  
To manually clear the session keys call clear_session_keys. This should be done for example as part of a session log off action.
=end  
  module CryptoSupport 
    
    def self.append_features(base) #:nodoc:
      super
      base.send :prepend_before_filter, :load_session_keys
      base.send :prepend_after_filter, :save_session_keys      
    end

=begin rdoc
Clears the session keys. Call this when a user logs of.
=end
    def clear_session_keys
      ActiveRecord::Base.clear_session_keys
    end
    
    
    private
    def load_session_keys
      if @session['session_keys']
        ActiveRecord::Base.session_keys=@session['session_keys']
      else
        ActiveRecord::Base.clear_session_keys
      end
    end

    def save_session_keys
      if ActiveRecord::Base.session_keys.size>0
        @session['session_keys']=ActiveRecord::Base.session_keys
      else
        @session['session_keys']=nil
      end
    end
    
  end

  class Base # :nodoc:
    include CryptoSupport
  end

end

class MissingKeyError < RuntimeError
end 
