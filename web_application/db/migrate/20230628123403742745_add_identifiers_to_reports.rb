class AddIdentifiersToReports < ActiveRecord::Migration[7.0]
    def change
      

      add_foreign_key :reports, :users, column: :user_id 
    end
  end
  