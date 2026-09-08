package metrics

// Value is a single exported metric datapoint: an id, a set of
// label tags and a float value.
type Value struct {
	ID    string            `json:"id"`
	Tags  map[string]string `json:"tags"`
	Value float64           `json:"value"`
}

func NewValue() Value {
	return Value{
		Tags: make(map[string]string),
	}
}
