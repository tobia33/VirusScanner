require "test_helper"

class HashesControllerTest < ActionDispatch::IntegrationTest
  test "should get new" do
    get hashes_new_url
    assert_response :success
  end

  test "should get create" do
    get hashes_create_url
    assert_response :success
  end
end
