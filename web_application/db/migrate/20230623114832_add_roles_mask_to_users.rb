class AddRolesMaskToUsers < ActiveRecord::Migration[7.0]
  def change
    add_column :users, :roles_mask, :integer, if_not_exists:true
  end
end
