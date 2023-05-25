class CreateReports < ActiveRecord::Migration[7.0]
  def change
    create_table :reports do |t|
      t.string :sha256
      t.string :url
      t.text :content

      t.timestamps
    end
  end
end
