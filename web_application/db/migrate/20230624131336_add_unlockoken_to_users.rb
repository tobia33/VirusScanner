class AddUnlockokenToUsers < ActiveRecord::Migration[7.0]
  def change
    add_column :users, :unlock_token, :string
  end
end
