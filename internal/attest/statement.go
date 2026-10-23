package attest

// DecodeStatement decodes one Sigstore bundle into its in-toto statement:
// the bundle's dsseEnvelope payload, base64 decoded, carries the statement
// JSON. It checks the payload type, the signature presence, the in-toto
// statement type and the subject digest shape.
//
// TR-81 RED stub: the GREEN commit fills the decode. The zero return with
// no error makes every decode contract test fail on camera until then.
func DecodeStatement(bundle Bundle) (Statement, error) {
	return Statement{}, nil
}
