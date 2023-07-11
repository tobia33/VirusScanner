require 'rails_helper'

RSpec.describe User, type: :model do
  describe "blocca" do
    context "given an unbanned user" do
        before do
          @user = create :user
        end
        it "is banned" do
            User.blocca(@user)
            expect(@user.access_locked?).to eql(true)
        end
    end
    context "given a banned user" do 
      before do
        @user = create :user
        @user.lock_access!
      end
      it "is unbanned" do
        User.blocca(@user)
        expect(@user.access_locked?).to eql(false)
      end
    end
  end
end
