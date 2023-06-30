# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[7.0].define(version: 20230628123403742745) do
  create_table "comments", force: :cascade do |t|
    t.text "body"
    t.integer "report_id", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["report_id"], name: "index_comments_on_report_id"
  end

  create_table "group_privileges", id: false, force: :cascade do |t|
    t.integer "group_id"
    t.integer "privilege_id"
    t.index ["group_id"], name: "index_group_privileges_on_group_id"
    t.index ["privilege_id"], name: "index_group_privileges_on_privilege_id"
  end

  create_table "group_roles", id: false, force: :cascade do |t|
    t.integer "group_id"
    t.integer "role_id"
    t.index ["group_id"], name: "index_group_roles_on_group_id"
    t.index ["role_id"], name: "index_group_roles_on_role_id"
  end

  create_table "groups", force: :cascade do |t|
    t.string "file_name"
    t.integer "user_id"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["user_id"], name: "index_groups_on_user_id"
  end

  create_table "notes", force: :cascade do |t|
    t.text "content"
    t.integer "report_id"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["report_id"], name: "index_notes_on_report_id"
  end

  create_table "privileges", force: :cascade do |t|
    t.string "name"
    t.text "description"
    t.string "controller"
    t.string "action"
    t.boolean "is_active"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "reports", force: :cascade do |t|
    t.string "sha256"
    t.string "url"
    t.text "content"
    t.string "score"
    t.integer "group_id"
    t.integer "user_id"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["group_id"], name: "index_reports_on_group_id"
    t.index ["user_id"], name: "index_reports_on_user_id"
  end

  create_table "role_users", id: false, force: :cascade do |t|
    t.integer "role_id"
    t.integer "user_id"
    t.index ["role_id"], name: "index_role_users_on_role_id"
    t.index ["user_id"], name: "index_role_users_on_user_id"
  end

  create_table "roles", force: :cascade do |t|
    t.string "role_name"
    t.text "role_description"
    t.boolean "is_active"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "users", force: :cascade do |t|
    t.string "email", default: "", null: false
    t.string "encrypted_password", default: "", null: false
    t.string "reset_password_token"
    t.datetime "reset_password_sent_at"
    t.datetime "remember_created_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.string "provider", limit: 50, default: ""
    t.string "uid", limit: 500, default: ""
    t.string "username"
    t.string "confirmation_token"
    t.datetime "confirmed_at"
    t.datetime "confirmation_sent_at"
    t.integer "roles_mask"
    t.datetime "locked_at"
    t.string "unlock_token"
    t.integer "failed_attempts", default: 0
    t.index ["confirmation_token"], name: "index_users_on_confirmation_token", unique: true
    t.index ["email"], name: "index_users_on_email", unique: true
    t.index ["reset_password_token"], name: "index_users_on_reset_password_token", unique: true
    t.index ["unlock_token"], name: "index_users_on_unlock_token", unique: true
    t.index ["username"], name: "index_users_on_username", unique: true
  end

  create_table "votes", force: :cascade do |t|
    t.string "value"
    t.string "verdict"
    t.integer "report_id", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["report_id"], name: "index_votes_on_report_id"
  end

  add_foreign_key "comments", "reports"
  add_foreign_key "groups", "users"
  add_foreign_key "groups", "users"
  add_foreign_key "notes", "reports"
  add_foreign_key "reports", "groups"
  add_foreign_key "reports", "users"
  add_foreign_key "reports", "users"
  add_foreign_key "votes", "reports"
end
