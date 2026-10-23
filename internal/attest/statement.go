package attest

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	wireStatementType = "https://in-toto.io/Statement/v1"
	wirePayloadType   = "application/vnd.in-toto+json"
)

// sigstoreBundle carries the wire shape of one Sigstore bundle object. The
// verifier reads the dsseEnvelope and a transparency-log presence marker;
// the cryptographic material itself stays unverified here and is checked
// by `gh attestation verify`.
type sigstoreBundle struct {
	VerificationMaterial struct {
		TlogEntries []json.RawMessage `json:"tlogEntries"`
	} `json:"verificationMaterial"`
	DSSEEnvelope struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Signatures  []struct {
			Sig string `json:"sig"`
		} `json:"signatures"`
	} `json:"dsseEnvelope"`
}

type statementDoc struct {
	Type          string       `json:"_type"`
	Subject       []subjectDoc `json:"subject"`
	PredicateType string       `json:"predicateType"`
	Predicate     struct {
		RunDetails struct {
			Builder struct {
				ID string `json:"id"`
			} `json:"builder"`
		} `json:"runDetails"`
	} `json:"predicate"`
}

type subjectDoc struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// DecodeStatement decodes one Sigstore bundle into its in-toto statement:
// the bundle's dsseEnvelope payload, base64 decoded, carries the statement
// JSON. It checks the dsse payload type, the signature presence, the
// transparency-log entry presence, the in-toto statement type and the
// subject digest shape. An undecodable bundle is an error, never a pass.
func DecodeStatement(bundle Bundle) (Statement, error) {
	var sig sigstoreBundle
	if err := json.Unmarshal(bundle, &sig); err != nil {
		return Statement{}, fmt.Errorf("sigstore bundle decode: %w", err)
	}
	if len(sig.VerificationMaterial.TlogEntries) == 0 {
		return Statement{}, errors.New("bundle carries no transparency-log entry")
	}
	env := sig.DSSEEnvelope
	if env.PayloadType != wirePayloadType {
		return Statement{}, fmt.Errorf("dsse payload type %s is not the in-toto type", env.PayloadType)
	}
	if len(env.Signatures) == 0 {
		return Statement{}, errors.New("dsse envelope carries no signature")
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return Statement{}, fmt.Errorf("dsse payload decode: %w", err)
	}
	var doc statementDoc
	if err := json.Unmarshal(payload, &doc); err != nil {
		return Statement{}, fmt.Errorf("in-toto statement decode: %w", err)
	}
	if doc.Type != wireStatementType {
		return Statement{}, fmt.Errorf("statement type %s is not the in-toto Statement/v1 form", doc.Type)
	}
	if len(doc.Subject) == 0 {
		return Statement{}, errors.New("statement carries no subject")
	}
	digests := make([]string, 0, len(doc.Subject))
	for _, s := range doc.Subject {
		if sha := s.Digest["sha256"]; sha != "" {
			digests = append(digests, "sha256:"+sha)
		}
	}
	if len(digests) == 0 {
		return Statement{}, errors.New("statement subject carries no sha256 digest")
	}
	return Statement{
		PredicateType:  doc.PredicateType,
		SubjectDigests: digests,
		Builder:        doc.Predicate.RunDetails.Builder.ID,
	}, nil
}
