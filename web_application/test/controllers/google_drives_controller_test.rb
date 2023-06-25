require "test_helper"

class GoogleDrivesControllerTest < ActionDispatch::IntegrationTest
  test "should get export" do
    get google_drives_export_url
    assert_response :success
  end

  test "should get import" do
    get google_drives_import_url
    assert_response :success
  end
end
