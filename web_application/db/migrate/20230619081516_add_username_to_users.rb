class AddUsernameToUsers < ActiveRecord::Migration[7.0]
  def change
    add_column :users, :username, :string, if_not_exists: true
    add_index :users, :username, unique: true, if_not_exists:true
  end
end
