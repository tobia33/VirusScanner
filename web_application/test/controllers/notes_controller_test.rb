require "test_helper"

class NotesControllerTest < ActionDispatch::IntegrationTest
  test "should get new" do
    get notes_new_url
    assert_response :success
  end

  test "should get create" do
    get notes_create_url
    assert_response :success
  end
end
