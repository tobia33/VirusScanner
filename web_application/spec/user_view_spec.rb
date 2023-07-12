require 'rails_helper'
require 'factories.user'

RSpec.describe "users/show", type: :view do
    let(:user) { create(:user) }
    let(:user2) {create(:user, id:200, username: "anselmo", email:" falsa@falsamail.it", password: 13934925445, roles_mask: 0)}
    let(:user3) {create(:user, id:203, username: "armando", email:" falsa2@fals2a22mail.it", password: 1393456536525445, roles_mask: 1)} 
    before do
        sign_in(user2)
        sign_in(user)
        sign_in(user3)
        user2.lock_access!
        allow(view).to receive(:current_user).and_return(user3)
        assign(:user, user3)
        render
    end
    it "displays common commands" do
        expect(rendered).to have_link("home")
        expect(rendered).to have_content(user3.email)
        expect(rendered).to have_button("Delete")
    end
    it "displays ban/unban buttons" do
        expect(rendered).to have_content(user2.email)
        expect(rendered).to have_content(user.email)
        expect(rendered).to have_button("Ban")
        expect(rendered). to have_button("Sblocca")
    end
end