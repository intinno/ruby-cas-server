require 'casserver/authenticators/sql_encrypted'

require 'digest/sha1'
require 'digest/md5'

begin
  require 'active_record'
rescue LoadError
  require 'rubygems'
  require 'active_record'
end

# This is a version of the SQL authenticator that works nicely with RestfulAuthentication.
# Passwords are encrypted the same way as it done in RestfulAuthentication.
# Before use you this, you MUST configure rest_auth_digest_streches and rest_auth_site_key in
# config.
#
# Using this authenticator requires restful authentication plugin on rails (client) side.
#
# * git://github.com/technoweenie/restful-authentication.git
#
class CASServer::Authenticators::SQLRestAuth < CASServer::Authenticators::SQLEncrypted

  def validate(credentials)
    read_standard_credentials(credentials)
    raise_if_not_configured

    user_model = self.class.user_model

    username_column = @options[:username_column] || "email"

    $LOG.debug "#{self.class}: [#{user_model}] " + "Connection pool size: #{user_model.connection_pool.instance_variable_get(:@checked_out).length}/#{user_model.connection_pool.instance_variable_get(:@connections).length}"
    results = user_model.find(:all, :conditions => ["#{username_column} = ?", @username])
    user_model.connection_pool.checkin(user_model.connection)

    if results.size > 0
      $LOG.warn("Multiple matches found for user '#{@username}'") if results.size > 1
      user = results.first
      if user.crypted_password == user.encrypt(@password)
        unless @options[:extra_attributes].blank?
          extract_extra(user)
          log_extra
        end
        return true
      else
        return false
      end
    else
      return false
    end
  end

  def self.setup(options)
    super(options)
    user_model.__send__(:include, EncryptedPassword)
  end

  module EncryptedPassword

    # XXX: this constants MUST be defined in config.
    # For more details # look at restful-authentication docs.
    #HACK HACK HACK: dunno how to do it so hardcoded these values
    #they should match with rails applications config
    REST_AUTH_DIGEST_STRETCHES =  15
    REST_AUTH_SITE_KEY         = '5a5e73a69a893311f859ccff1ffd0fa2d7ea25fd' 

    def self.included(mod)
      raise "#{self} should be inclued in an ActiveRecord class!" unless mod.respond_to?(:before_save)
    end

    def encrypt(password)
	if self.old_portal
Digest::MD5.hexdigest(password)
	else
password_digest(password, self.salt)
	end
    end

    def secure_digest(*args)
      Digest::SHA1.hexdigest(args.flatten.join('--'))
    end

    def password_digest(password, salt)
      digest = REST_AUTH_SITE_KEY
      REST_AUTH_DIGEST_STRETCHES.times do
        digest = secure_digest(digest, salt, password, REST_AUTH_SITE_KEY)
      end
      digest
    end
  end
end
