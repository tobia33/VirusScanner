require "test_helper"

class BehaviorReportsControllerTest < ActionDispatch::IntegrationTest
  test "should get show" do
    get behavior_reports_show_url
    assert_response :success
  end
end
