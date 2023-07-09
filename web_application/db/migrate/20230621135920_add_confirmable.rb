class AddConfirmable < ActiveRecord::Migration[7.0]
  def self.up
    add_column :users, :confirmation_token, :string, if_not_exists: true
    add_column :users, :confirmed_at, :datetime, if_not_exists: true
    add_column :users, :confirmation_sent_at, :datetime, if_not_exists: true

    add_index :users, :confirmation_token, :unique => true, if_not_exists: true
  end
  def self.down
    remove_index :users, :confirmation_token

    remove_column :users, :confirmation_sent_at
    remove_column :users, :confirmed_at
    remove_column :users, :confirmation_token
  end
end
