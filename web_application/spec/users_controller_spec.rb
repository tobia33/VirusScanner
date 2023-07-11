require 'rails_helper'
require 'factories.user'

RSpec.describe UsersController, type: :controller do
    describe ".ban" do
        context "created a new user" do
            before do
                @user = create :user
            end
            it "is unbanned by default" do
                expect(@user.access_locked?).to eql(false)
            end
        end
    end
end
