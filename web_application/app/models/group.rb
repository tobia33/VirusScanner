class Group < ApplicationRecord
    has_many :reports, dependent: :destroy
end
