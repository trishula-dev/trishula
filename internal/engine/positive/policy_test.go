package positive

// policy_test.go holds the strict-load contract table; the drive loop in
// positive_test.go runs it through the real LoadPolicy.
var greenStrictCases = []struct {
	name, wantErr string
}{
	{name: "ref_indirection", wantErr: `"$ref" is not allowed`},
	{name: "unsupported_field_name", wantErr: `"format" is not allowed`},
	{name: "unknown_keyword", wantErr: `"if" is not allowed`},
}
