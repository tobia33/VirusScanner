class CreateReports < ActiveRecord::Migration[7.0]
  def change
    create_table :reports do |t|
      t.references :u_file, null: false, foreign_key: true
      t.text :contenuto
      t.timestamp :last_scan

      t.timestamps
    end
  end
end
