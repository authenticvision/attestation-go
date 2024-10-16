package attestation

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type SLID36 string

func NewCanonicalSLID36(slid36 string) (SLID36, error) {
	slid, err := strconv.ParseInt(string(slid36), 36, 64)
	if err != nil {
		return "", fmt.Errorf("failed to parse SLID as base36: %w", err)
	}
	if slid <= 0 {
		return "", errors.New("not a positive 64-bit integer")
	}
	return SLID36(strings.ToUpper(strconv.FormatInt(slid, 36))), nil
}
