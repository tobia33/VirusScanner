class CreateComments < ActiveRecord::Migration[7.0]
  def change
    unless table_exists? :comments
      create_table :comments do |t|
        t.text :body
        t.references :report, null: false, foreign_key: true

        t.timestamps
      end
    end
  end
end
