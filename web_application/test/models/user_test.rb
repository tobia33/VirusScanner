require "test_helper"

class UserTest < ActiveSupport::TestCase
  # test "the truth" do
  #   assert true
  # end
  test "sign in" do
    @request.env['devise.mapping'] = Devise.mappings[:users]

    sing_in users[:ezio]
    
    get :new
  end
end
