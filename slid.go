package attestation

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var ErrInvalidSLID = errors.New("not a positive 64-bit integer")

type SLID int64

func (slid SLID) String() string {
	return slid.Base36()
}

func (slid SLID) Base10() string {
	return strconv.FormatInt(int64(slid), 10)
}

func (slid SLID) Base36() string {
	return strings.ToUpper(strconv.FormatInt(int64(slid), 36))
}

// SLID36 is a raw text SLID with base36-encoded contents
type SLID36 string

// SLID decodes the SLID for use as 64-bit integer
func (slid SLID36) SLID() (SLID, error) {
	i, err := strconv.ParseInt(string(slid), 36, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse SLID as base36: %w", err)
	}
	if i <= 0 {
		return 0, ErrInvalidSLID
	}
	return SLID(i), nil
}
