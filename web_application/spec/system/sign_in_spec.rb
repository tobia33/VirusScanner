#require "rails_helper"

#describe "User signs in", type: :system do
#  before do
#    @user = create :user
#    visit new_user_session_path
#  end

#  scenario "valid with correct credentials" do
#    fill_in "user_email", with: @user.email
#    fill_in "user_password", with: @user.password
#    click_button "sign in"
#
#    expect(page).to have_text "Welcome back"
#    find('#user-menu-button').click
#    expect(page).to have_link "Sign out"
#    expect(page).to have_current_path root_path
#  end
#end