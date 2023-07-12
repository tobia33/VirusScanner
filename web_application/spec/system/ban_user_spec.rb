require "rails_helper"
require 'factories.user'

describe "user page", type: :system do
    let(:user) { create(:user, id:300, username: "horatio", email:" falsa489@falsamail.it", password: 13934925448487395, roles_mask: 0)  }
    let(:user2) {create(:user, id:200, username: "anselmo", email:" falsa@falsamail.it", password: 13934925445, roles_mask: 0)}
    let(:user3) {create(:user, id:203, username: "armando", email:" falsa2@fals2a22mail.it", password: 1393456536525445, roles_mask: 1)}
    before do
        sign_in(user)
        sign_in(user2)
        sign_in(user3)
        user2.lock_access!
        @user = User.create(id: 1000,username: 'example', email: 'example@example.com', 
                            password: 'password', created_at: Date.today ,confirmed_at: Date.today, roles_mask:1)
        sign_in(@user)
        allow(controller).to receive(:current_user).and_return(user3)
        visit root_path
        click_link "pagina degli utenti"
    end

    scenario "click ban button" do
        click_button "Ban"
        expect(page).to have_no_button("Ban")
        expect(user2.access_locked?).to eql(true)
    end

    scenario "click unban button" do
        click_button "Sblocca"
        expect(page).to have_no_button("Sblocca")
        expect(user.access_locked?).to eql(false)
    end
end

describe "user page without no admin users", type: :system do
    let(:user3) {create(:user, id:203, username: "armando", email:" falsa2@fals2a22mail.it", password: 1393456536525445, roles_mask: 1)}
    before do
        sign_in(user3)
        @user = User.create(id: 1000,username: 'example', email: 'example@example.com', 
                            password: 'password', created_at: Date.today ,confirmed_at: Date.today, roles_mask:1)
        sign_in(@user)
        allow(controller).to receive(:current_user).and_return(user3)
        visit root_path
        click_link "pagina degli utenti"
    end
    
    scenario "no button to ban/unban" do        
        expect(page).to have_no_button("Ban")
        expect(page).to have_no_button("Sblocca")
        expect(page).to have_link("home")
        expect(page).to have_link("pagina degli utenti")
        expect(page).to have_button("Log out")
        expect(page).to have_content(user3.email)
        expect(page).to have_content(@user.email)
    end
end
