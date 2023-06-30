class CreateNotes < ActiveRecord::Migration[7.0]
  def change
    create_table :notes do |t|
      t.text :content
      t.references :report, foreign_key: true
      t.timestamps
    end
  end
end
