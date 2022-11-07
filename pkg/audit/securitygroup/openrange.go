package securitygroup

import (
	"fmt"
)

type OpenRange struct {
	Protocol string
	From     string
	To       string
}

func (o OpenRange) ToString() string {
	if o.Protocol == "" && o.From == "" && o.To == "" {
		return "Unknown"
	}

	if o.To == "" {
		return fmt.Sprintf("%s: %s", o.Protocol, o.From)
	}

	return fmt.Sprintf("%s: %s-%s", o.Protocol, o.From, o.To)
}
