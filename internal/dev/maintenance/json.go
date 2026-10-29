package maintenance

import "encoding/json"

func decodeJSON(data []byte, value any) error { return json.Unmarshal(data, value) }
func asObject(value any) (object, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	var out object

	err = json.Unmarshal(data, &out)

	return out, err
}
