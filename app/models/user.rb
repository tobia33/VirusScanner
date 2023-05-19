class User < ApplicationRecord
  has_many :sessions
  has_many :u_files

  validates :username, presence: true
  validates :password, presence: true
  validates :admin, presence: true
end
