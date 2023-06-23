class CreateGroupRoles < ActiveRecord::Migration[7.0]
  def change
    create_table :group_roles, :id => false do |t|
	  t.references :group
      t.references :role
    end
  end
end
