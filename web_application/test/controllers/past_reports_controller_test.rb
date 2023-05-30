require "test_helper"

class PastReportsControllerTest < ActionDispatch::IntegrationTest
  test "should get index" do
    get past_reports_index_url
    assert_response :success
  end
end
