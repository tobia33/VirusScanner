require "test_helper"

class BinariesControllerTest < ActionDispatch::IntegrationTest
  test "should get new" do
    get binaries_new_url
    assert_response :success
  end

  test "should get create" do
    get binaries_create_url
    assert_response :success
  end
end
