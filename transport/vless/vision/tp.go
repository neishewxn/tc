package vision

import (
	"reflect"

	utls "github.com/neishewxn/utls"
)

type SimpleType interface {
	FieldByName(name string) (reflect.StructField, bool)
}

var utlsType SimpleType

func init() {
	utlsType = CreateOnceType[utls.Conn]()
}

type OnceType struct {
	inputOffset    uintptr
	rawInputOffset uintptr
}

func CreateOnceType[T any]() *OnceType {
	var onceType OnceType
	t := reflect.TypeFor[T]()
	if i, ok := t.FieldByName("input"); ok {
		onceType.inputOffset = i.Offset
	} else {
		panic("invalid type for OnceType, missing field: input")
	}
	if i, ok := t.FieldByName("rawInput"); ok {
		onceType.rawInputOffset = i.Offset
	} else {
		panic("invalid type for OnceType, missing field: rawInput")
	}
	return &onceType
}

func (u *OnceType) FieldByName(name string) (reflect.StructField, bool) {
	var offset uintptr
	switch name {
	case "input":
		offset = u.inputOffset
	case "rawInput":
		offset = u.rawInputOffset
	default:
		return reflect.StructField{}, false
	}
	return reflect.StructField{Offset: offset}, true
}
