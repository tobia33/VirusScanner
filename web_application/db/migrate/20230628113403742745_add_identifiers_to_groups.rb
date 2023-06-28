class AddIdentifiersToGroups < ActiveRecord::Migration[7.0]
    def change
      add_column :groups, :user_id, :integer
      add_index :groups, :user_id, unique: true 
      add_foreign_key :groups, :users, column: :user_id
    end
  end
  