package maintenance

import "encoding/json"

func asObject(value any) (object, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	var out object

	err = json.Unmarshal(data, &out)

	return out, err
}
