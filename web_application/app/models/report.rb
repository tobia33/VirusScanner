class Report < ApplicationRecord
    has_many :comments, dependent: :destroy
    has_many :votes, dependent: :destroy    
    has_many :notes, dependent: :destroy

    belongs_to :group, optional: true
    belongs_to :user
end
