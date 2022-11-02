package secret

import (
	"fmt"
	"testing"
)

func TestEngine(t *testing.T) {
	engine := NewEngine(false)
	findings := engine.Scan("AKIAIOSFODNN7EXAMPLE  wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	fmt.Println(findings)
}
