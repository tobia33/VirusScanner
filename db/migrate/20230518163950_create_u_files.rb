class CreateUFiles < ActiveRecord::Migration[7.0]
  def change
    create_table :u_files do |t|
      t.references :user, null: false, foreign_key: true
      t.string :nome
      t.string :hash
      # t.integer :file_id_ext

      t.timestamps
    end
  end
end
