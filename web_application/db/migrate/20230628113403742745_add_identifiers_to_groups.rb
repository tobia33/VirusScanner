class AddIdentifiersToGroups < ActiveRecord::Migration[7.0]
    def change

      add_foreign_key :groups, :users, column: :user_id, if_not_exists: true
    end
  end
  