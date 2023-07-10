require "rails_helper"

describe "User logs out", type: :system do
    
    WebMock.disable_net_connect!(:allow_localhost => true)
    before do
        @user = User.create(id: 1000,username: 'example', email: 'example@example.com', 
                            password: 'password', created_at: Date.today ,confirmed_at: Date.today)
        sign_in(@user)
        visit root_path
    end

  scenario "log out" do
    click_button "Log out"

    expect(page).to have_text "You need to sign in or sign up before continuing"
    expect(page).to have_current_path new_user_session_path
  end
end