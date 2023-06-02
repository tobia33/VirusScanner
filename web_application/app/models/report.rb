class Report < ApplicationRecord
    has_many :comments, dependent: :destroy
    has_many :votes, dependent: :destroy
    belongs_to :group, optional: true
end
