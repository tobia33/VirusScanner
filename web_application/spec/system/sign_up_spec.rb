require "rails_helper"

describe "User signs up", type: :system do
  let(:username) { Faker::Internet.username }
  let(:email) {Faker::Internet.email}
  let(:password) { Faker::Internet.password(min_length: 8) }

  WebMock.disable_net_connect!(:allow_localhost => true)
  before do
    visit new_user_registration_path
  end

  scenario "with valid data" do
    fill_in "user_username", with: username
    fill_in "user_email", with: email
    fill_in "user_password", with: password
    fill_in "user_password_confirmation", with: password
    click_button "Sign up"

    expect(page).to have_text "You need to sign in or sign up before continuing."
  end
end