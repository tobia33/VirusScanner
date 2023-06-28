class AddIdentifiersToReports < ActiveRecord::Migration[7.0]
    def change
      add_column :reports, :user_id, :integer
      add_index :reports, :user_id, unique: true
      add_foreign_key :reports, :users, column: :user_id 
    end
  end
  