require "test_helper"

class ManageReportsControllerTest < ActionDispatch::IntegrationTest
  test "should get download" do
    get manage_reports_download_url
    assert_response :success
  end

  test "should get upload" do
    get manage_reports_upload_url
    assert_response :success
  end
end
