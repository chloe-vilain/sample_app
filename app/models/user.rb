class User < ApplicationRecord
  #Generates getter and setter functions for an attribute
  attr_accessor :remember_token

  before_save { email.downcase! }
  validates :name, presence: true, length: { maximum: 50 }
  VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i
  validates :email, presence: true, length: { maximum: 255 },
                    format: { with: VALID_EMAIL_REGEX },
                    uniqueness: { case_sensitive: false }
  has_secure_password
  validates :password, presence: true, length: { minimum: 6 }, allow_nil: true

  #Returns a hash digest of a given string. Uses minimum costs in test to
  #improve performance and highest cost in prod for security
  def User.digest(string)
    cost = ActiveModel::SecurePassword.min_cost ? BCrypt::Engine::MIN_COST :
                                                  BCrypt::Engine.cost
    BCrypt::Password.create(string, cost: cost)
  end

  #Generates random token to be used as remember token
  #Returns a string
  def User.new_token
    SecureRandom.urlsafe_base64
  end

  #Sets user attribute remember_token to a new random token genetated by
  #User.new_token
  #Creates remember_digest attributes and updates the remember_digest value
  #in the Users table using the User.digest function, which hashes the
  #User.remember_token string
  def remember
    self.remember_token = User.new_token
    update_attribute(:remember_digest, User.digest(remember_token))
  end

  # checks if a remember_token string passed matches the hashed remember_digest
  # for the user.
  # Returns false if there is no remember_digest attribute for the user.
  def authenticated?(remember_token)
    return false if remember_digest.nil?
    BCrypt::Password.new(remember_digest).is_password?(remember_token)
  end

  #Updates the remember_digest value to nil to terminate the session
  def forget
    update_attribute(:remember_digest, nil)
  end

end
