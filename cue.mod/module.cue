// The CUE module of the tree (TR-46): the declarative layer for the
// structured artefacts the tree owns. The module path matches the Go module
// path so CUE package paths read as repo paths. Consumers:
//
//   - internal/cuegen (the generator; the golden-diff artefact source)
//   - cue vet (the CI gate)
//   - the structure tests (the CUE Go API)
module: "github.com/trishula-dev/trishula"
language: version: "v0.9.0"
