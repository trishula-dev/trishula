package cel

import (
	"fmt"

	"sigs.k8s.io/yaml"
)

// RequestCase is one fixture case: a §11.3 request sample plus the expected
// verdict for the seed rule. JSON tags rule the decode (see Request).
type RequestCase struct {
	Name     string      `yaml:"name" json:"name"`
	Request  Request     `yaml:"request" json:"request"`
	Expected Expectation `yaml:"expected" json:"expected"`
}

// Expectation is the expected verdict of a fixture case. Error=true says the
// eval must fail (structurally), not that the rule must match.
type Expectation struct {
	Match bool `yaml:"match" json:"match"`
	Error bool `yaml:"error" json:"error"`
}

// ParseRequestCases decodes a sample-request fixture YAML document
// (internal/engine/cel/testdata/sample_request.yaml).
func ParseRequestCases(data []byte) ([]RequestCase, error) {
	var fixture struct {
		Cases []RequestCase `yaml:"cases"`
	}
	if err := yaml.Unmarshal(data, &fixture); err != nil {
		return nil, fmt.Errorf("parse request cases: %w", err)
	}
	if len(fixture.Cases) == 0 {
		return nil, fmt.Errorf("parse request cases: empty cases list")
	}
	return fixture.Cases, nil
}
