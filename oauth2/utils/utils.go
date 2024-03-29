package utils

import "reflect"

func ToMap(val interface{}, defaultVal map[string]string) map[string]string {
	if val == nil {
		return defaultVal
	}
	kind := reflect.TypeOf(val).Kind()
	if kind == reflect.Map {
		return val.(map[string]string)
	}
	return defaultVal
}
