class Update < ActiveRecord::Migration[7.0]
  def change
    add_column :users, :provider, :string, limit: 50, default: '', if_not_exists: true
    add_column :users, :uid, :string, limit: 500, default: '', if_not_exists: true
  end
end
