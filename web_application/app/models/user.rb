class User < ApplicationRecord
  has_many :reports, dependent: :destroy
  has_many :groups, dependent: :destroy
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable,
         :confirmable, :lockable, :timeoutable,
         :omniauthable, omniauth_providers: [:google_oauth2],
         :authentication_keys => [:username]

  #acts_as_user :roles => [ :normaluser, :admin ]

  ROLES = %i[admin normaluser not_rescan not_votes not_comments not_mitre not_behavior]

  def roles!(roles)
    roles = [*roles].map { |r| r.to_sym }
    self.roles_mask += (roles & ROLES).map { |r| 2**ROLES.index(r) }.inject(0, :+)
  end

  def remove_roles!(roles)
    roles = [*roles].map { |r| r.to_sym }
    self.roles_mask -= (roles & ROLES).map { |r| 2**ROLES.index(r) }.inject(0, :+)
  end

  def roles
    ROLES.reject do |r|
      ((roles_mask.to_i || 0) & 2**ROLES.index(r)).zero?
    end
  end

  def has_role?(role)
    self.roles.include?(role)
  end

  def self.create_from_provider_data(provider_data)
    where(provider: provider_data.provider, uid: provider_data.uid).first_or_create  do |user|
      user.email = provider_data.info.email
      user.password = Devise.friendly_token[0, 20]
    end
  end
end

