require 'rails_helper'
require 'factories.report'
require 'factories.user'
require 'factories.group'

RSpec.describe "reports/show", type: :view do
  #let(:report) { create(:report) }
  let(:user) { create(:user) }
  let(:group) { create(:group, user: user) }
  let(:report) { create(:report, user: user, group: group) }

  before do
    assign(:report, report)
    allow(view).to receive(:current_user).and_return(user)
    render
  end

  it "displays the report details" do
    expect(rendered).to have_content(report.sha256)
    expect(rendered).to have_content(report.score)
    expect(rendered).to have_content(report.url)
  end
  it "displays the links for navigation" do
    expect(rendered).to have_link("home", href: reports_path)
    expect(rendered).to have_link("download report", href: "/manage_reports/download?id=#{report.id}")
    expect(rendered).to have_link("add note", href: new_note_path(report_id: report.id))
    expect(rendered).to have_link("edit report", href: edit_report_path(report.id))


    if report.sha256 && !user.has_role?(:not_rescan)
        sha256 = Base64.encode64(report.sha256)
        expect(rendered).to have_link("rescan report", href: rescan_report_path(sha256))
      end
  
      # Add more link expectations as needed
    end
    it "displays the report content" do
        # Replace the JSON parsing logic with appropriate test data
        content = { "data" => { "attributes" => { "results" => { "category" => "Category", "result" => "Result", "method" => "Method" } } } }
        report.update(content: content.to_json)
    
        expect(rendered).to have_content("SCORE")
        expect(rendered).to have_content("CONTENT")
      end

      it "displays comments, votes, and notes when allowed" do
        # Enable the relevant user roles to display comments, votes, and notes
        allow(controller).to receive(:current_user).and_return(double("user", has_role?: false))
        
        expect(rendered).to have_content("COMMENTS")
        expect(rendered).to have_content("VOTES")
        expect(rendered).to have_content("NOTES")
      end
    end