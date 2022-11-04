package buildspec

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Env is an optional sequence. Represents information for one or more custom environment variables.
type Env struct {
	Shell     string            `json:"shell,omitempty"`
	Variables map[string]string `json:"variables,omitempty"`
}

type Buildspec struct {
	Version string `json:"version"`
	RunAs   string `json:"run-as,omitempty"`
	Env     Env    `json:"env,omitempty"`
}

func ParseJSONString(input string) (*Buildspec, error) {
	var buildspec Buildspec

	if !strings.Contains(input, "\"version\":") {
		return nil, fmt.Errorf("no buildspec: %s", input)
	}

	if err := json.Unmarshal([]byte(input), &buildspec); err != nil {
		return nil, fmt.Errorf("invalid JSON: %s", err)
	}

	return &buildspec, nil
}
