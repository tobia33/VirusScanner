class CreateRoleUsers < ActiveRecord::Migration[7.0]
  def change
    unless table_exists? :role_users
      create_table :role_users, :id => false do |t|
        t.references :role
        t.references :user
      end
    end
  end
end
