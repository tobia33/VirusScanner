class AddFailedAttemptsToUsers < ActiveRecord::Migration[7.0]
  def change
    add_column :users, :failed_attempts, :integer, default: 0, if_not_exists: true
    add_index :users, :unlock_token, unique: true, if_not_exists: true
  end
end
