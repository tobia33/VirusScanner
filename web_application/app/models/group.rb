class Group < ApplicationRecord
    has_many :reports, dependent: :destroy
    belongs_to :user, dependent: :destroy
end
