require "rails_helper"

describe "User signs up", type: :system do
  let(:username) { Faker::Internet.username }
  let(:usernamegiainuso) {Faker::Internet.username }
  let(:email) {Faker::Internet.email}
  let(:password) { Faker::Internet.password(min_length: 8) }
  let(:wrong_password) {Faker::Internet.password}

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

  scenario "with invalid data, different passwords" do
    fill_in "user_username", with: username
    fill_in "user_email", with: email
    fill_in "user_password", with: wrong_password
    fill_in "user_password_confirmation", with: password
    click_button "Sign up"

    expect(page).to have_text "Error, email already exists or some fields aren't filled correctly"
  end

  before do
    @user = User.create(username: usernamegiainuso, email: 'emaildiesempio@mail.com', password: 'passwordpocosicura')
  end

  scenario "with invalid data, username already in use" do
    fill_in "user_username", with: usernamegiainuso
    fill_in "user_email", with: email
    fill_in "user_password", with: wrong_password
    fill_in "user_password_confirmation", with: password
    click_button "Sign up"

    expect(page).to have_text "Username already exist"
  end
end