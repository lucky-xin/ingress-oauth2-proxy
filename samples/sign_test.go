package samples

import (
	"fmt"
	"testing"
)

func TestSignRequest(t *testing.T) {

	params := map[string]interface {
	}{
		"foo": "bar",
		"baz": "qux",
		"map": map[string]interface{}{
			"foo": "bar",
			"baz": "qux",
		},
	}
	m := params["map"].(map[string]interface{})
	fmt.Println(m)
	params["map"] = nil
	if m1, ok := params["map"].(map[string]interface{}); ok {
		fmt.Println(m1)
	}
}
