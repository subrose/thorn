package main

import (
	"fmt"
	"reflect"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type DynamicField struct {
	Name string
	Type reflect.Type
}

func CreateDynamicStruct(fields []DynamicField) reflect.Type {
	var structFields []reflect.StructField
	for _, field := range fields {
		structField := reflect.StructField{
			Name: field.Name,
			Type: field.Type,
			Tag:  reflect.StructTag(`gorm:"column:` + field.Name + `"`),
		}
		structFields = append(structFields, structField)
	}
	return reflect.StructOf(structFields)
}

func MigrateDynamicTable(db *gorm.DB, tableName string, fields []DynamicField) {
	dynamicType := CreateDynamicStruct(fields)
	dynamicValue := reflect.New(dynamicType).Elem().Interface()

	// Migrate the table
	db.Table(tableName).AutoMigrate(&dynamicValue)
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	// Define the fields of your dynamic table
	fields := []DynamicField{
		{"Name", reflect.TypeOf(string(""))},
		{"Age", reflect.TypeOf(int(0))},
	}

	// Migrate the table
	MigrateDynamicTable(db, "dynamic_people", fields)

	fmt.Println("Table created successfully!")
}
