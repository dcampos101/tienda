class CreateProducts < ActiveRecord::Migration[5.0]
  def change
    create_table :products do |t|
      t.references :category, foreign_key: true
      t.string :nombre
      t.text :descripcion
      t.float :precio
      t.integer :cantidad

      t.timestamps
    end
  end
end
