class CreateRoles < ActiveRecord::Migration[7.0]
  def change
    unless table_exists? :roles
      create_table :roles do |t|
        t.string :role_name
        t.text :role_description
        t.boolean :is_active

        t.timestamps null: false
      end
    end
  end
end
