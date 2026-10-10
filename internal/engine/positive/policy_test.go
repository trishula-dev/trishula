package positive

// greenLoadPolicy is the RED-state function variable standing in for
// GREEN's LoadPolicy(path string) (*Policy, error); the strict-load
// table in TestLoadStrict drives it (GREEN binds the real loader — this
// var dies with the RED commit).
var greenLoadPolicy func(path string) (*greenPolicy, error)
