class Report < ApplicationRecord
    has_many :comments
    has_many :votes
    belongs_to :group, optional: true
end
