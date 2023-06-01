require "test_helper"

class MitreReportsControllerTest < ActionDispatch::IntegrationTest
  test "should get show" do
    get mitre_reports_show_url
    assert_response :success
  end
end
