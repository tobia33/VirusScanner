class CreateGroupPrivileges < ActiveRecord::Migration[7.0]
  def change
    unless table_exists? :group_privileges
      create_table :group_privileges, :id => false do |t|
        t.references :group
        t.references :privilege
      end
    end
  end
end
