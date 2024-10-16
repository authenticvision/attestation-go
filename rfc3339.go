package attestation

import (
	"encoding/json"
	"time"
)

type RFC3339Time time.Time

func (t RFC3339Time) Time() time.Time {
	return time.Time(t)
}

func (t RFC3339Time) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(t).Format(time.RFC3339))
}

func (t *RFC3339Time) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return err
	}
	*t = RFC3339Time(parsed)
	return nil
}
