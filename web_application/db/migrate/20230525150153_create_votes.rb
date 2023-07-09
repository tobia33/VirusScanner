class CreateVotes < ActiveRecord::Migration[7.0]
  def change
    unless table_exists? :votes
      create_table :votes do |t|
        t.string :value
        t.string :verdict
        t.references :report, null: false, foreign_key: true

        t.timestamps
      end
    end
  end
end
