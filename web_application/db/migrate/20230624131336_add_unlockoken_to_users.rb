class AddUnlockokenToUsers < ActiveRecord::Migration[7.0]
  def change
    add_column :users, :unlock_token, :string, if_not_exists: true
  end
end
