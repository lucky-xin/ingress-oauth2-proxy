package utils

import "reflect"

func ToMap(val interface{}, defaultVal map[string]interface{}) map[string]interface{} {
	if val == nil {
		return defaultVal
	}
	kind := reflect.TypeOf(val).Kind()
	if kind == reflect.Map {
		return val.(map[string]interface{})
	}
	return defaultVal
}
