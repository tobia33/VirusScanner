require "rails_helper"

describe "User signs in", type: :system do
    
    before :each do        
        @user1 = User.create(username: 'example1', email: 'example1@example.com', password: 'password')
        @user2 = User.create(username: 'example2', email: 'example2@example.com', password: 'password', confirmed_at: Date.today)
        visit new_user_session_path
    end

  scenario "valid with correct credentials but mail address not confirmed" do
    fill_in "user_username", with: @user1.username
    fill_in "user_password", with: @user1.password
    click_button "Log in"

    expect(page).to have_text "You have to confirm your email address before continuing"
  end

  scenario "valid with correct credentials and mail address confirmed" do
    fill_in "user_username", with: @user2.username
    fill_in "user_password", with: @user2.password
    click_button "Log in"

    expect(page).to have_text "Signed in successfully"
  end
end