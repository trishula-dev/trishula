package v1alpha1

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	validation "k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/yaml"
)

// wafPolicyYAML is the TR-08a acceptance fixture: a WAFPolicy carrying the
// full minimal surface (metadata, one rule-set ref, a default action, the
// mode flags), reduced from the §19.1 WAFPolicy sketch.
const wafPolicyYAML = `apiVersion: trishula.security/v1alpha1
kind: WAFPolicy
metadata:
  name: chat-completions
  namespace: ai-platform
spec:
  defaultAction: block
  modeFlags:
    inline: true
    shield: true
    shadow: false
  ruleSets:
  - name: owasp-crs
    source:
      crsVersion: "4.x"
      profile: PL2
`

// generatedCRDPath is the controller-gen artifact under version control.
const generatedCRDPath = "manifests/crd/wafpolicy-crd.yaml"

// controllerGenVersion is the pinned deterministic generation tool version;
// the same invocation is recorded in the TR-08a PR body.
const controllerGenVersion = "v0.19.0"

// TestWAFPolicySchemeRoundTrip proves the CRD acceptance fixture decodes
// through a scheme carrying the registered trishula.security/v1alpha1 type,
// pins every field of the TR-08a surface, and round-trips through the
// scheme's YAML encoding into an equal object.
func TestWAFPolicySchemeRoundTrip(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	codecs := serializer.NewCodecFactory(scheme)

	obj, gvk, err := codecs.UniversalDeserializer().Decode([]byte(wafPolicyYAML), nil, nil)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	wantGVK := GroupVersion.WithKind("WAFPolicy")
	if gvk == nil || *gvk != wantGVK {
		t.Fatalf("decoded gvk: got %v, want %v", gvk.GroupVersion().String()+"/"+gvk.Kind, wantGVK)
	}
	wp, ok := obj.(*WAFPolicy)
	if !ok {
		t.Fatalf("decoded type %T, want *WAFPolicy", obj)
	}

	if wp.Spec.DefaultAction != DefaultActionBlock {
		t.Errorf("spec.defaultAction: got %q, want %q", wp.Spec.DefaultAction, DefaultActionBlock)
	}
	if !wp.Spec.ModeFlags.Inline {
		t.Errorf("spec.modeFlags.inline: got %v, want true", wp.Spec.ModeFlags.Inline)
	}
	if !wp.Spec.ModeFlags.Shield {
		t.Errorf("spec.modeFlags.shield: got %v, want true", wp.Spec.ModeFlags.Shield)
	}
	if wp.Spec.ModeFlags.Shadow {
		t.Errorf("spec.modeFlags.shadow: got %v, want false", wp.Spec.ModeFlags.Shadow)
	}
	if len(wp.Spec.RuleSets) != 1 {
		t.Fatalf("spec.ruleSets: got %d entries, want 1", len(wp.Spec.RuleSets))
	}
	rs := wp.Spec.RuleSets[0]
	if rs.Name != "owasp-crs" {
		t.Errorf("spec.ruleSets[0].name: got %q, want %q", rs.Name, "owasp-crs")
	}
	if rs.Source.CRSVersion != "4.x" {
		t.Errorf("spec.ruleSets[0].source.crsVersion: got %q, want %q", rs.Source.CRSVersion, "4.x")
	}
	if rs.Source.Profile != CRSProfilePL2 {
		t.Errorf("spec.ruleSets[0].source.profile: got %q, want %q", rs.Source.Profile, CRSProfilePL2)
	}

	info, ok := runtime.SerializerInfoForMediaType(codecs.SupportedMediaTypes(), "application/yaml")
	if !ok {
		t.Fatalf("no application/yaml serializer registered by the codec factory")
	}
	encoded, err := runtime.Encode(codecs.EncoderForVersion(info.Serializer, GroupVersion), wp)
	if err != nil {
		t.Fatalf("encode round-trip: %v", err)
	}
	wp2, gvk2, err := codecs.UniversalDeserializer().Decode(encoded, nil, nil)
	if err != nil {
		t.Fatalf("re-decode encoded form: %v", err)
	}
	if gvk2 == nil || *gvk2 != wantGVK {
		t.Fatalf("re-decode gvk: got %v, want %v", gvk2.GroupVersion().String()+"/"+gvk2.Kind, wantGVK)
	}
	if !reflect.DeepEqual(wp, wp2) {
		t.Errorf("round-trip mismatch:\nfixture: %+v\nencoded: %+v", wp, wp2)
	}
}

// TestWAFPolicyCRDGenerationDeterministic pins the delivery invariant for
// manifests/crd/wafpolicy-crd.yaml: a fresh pinned controller-gen run
// reproduces the committed artifact byte-for-byte, and a second fresh run
// is byte-identical to the first (generation is deterministic; the committed
// manifest is never hand-edited).
func TestWAFPolicyCRDGenerationDeterministic(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	runA, runB := generateCRD(t, dirA), generateCRD(t, dirB)

	if !bytes.Equal(runA, runB) {
		i := firstDiff(runA, runB)
		t.Fatalf("controller-gen %s is not deterministic: run A and run B diverge at byte %d (%q vs %q)",
			controllerGenVersion, i, showByte(runA, i), showByte(runB, i))
	}

	committed, err := os.ReadFile(filepath.Join(moduleRoot(t), filepath.FromSlash(generatedCRDPath)))
	if err != nil {
		t.Fatalf("read committed %s: %v", generatedCRDPath, err)
	}
	if !bytes.Equal(runA, committed) {
		i := firstDiff(runA, committed)
		t.Errorf("committed %s is stale: diverges from a fresh controller-gen %s run at byte %d (%q vs %q)",
			generatedCRDPath, controllerGenVersion, i, showByte(runA, i), showByte(committed, i))
	}

	// Content pins over the committed artifact: the generated manifest is
	// the WAFPolicy CRD for the trishula.security group, produced by the
	// pinned controller-gen (the annotation carries the tool version).
	for _, want := range []string{
		"name: wafpolicies.trishula.security",
		"group: trishula.security",
		"kind: WAFPolicy",
		"controller-gen.kubebuilder.io/version: " + controllerGenVersion,
	} {
		if !strings.Contains(string(committed), want) {
			t.Errorf("committed %s missing %q", generatedCRDPath, want)
		}
	}
}

// TestWAFPolicySchemaValidationApplyParse validates the CRD acceptance
// path the way kubectl apply meets the apiserver: the unstructured manifest
// from YAML is checked against the committed CRD's OpenAPI schema through
// the Kubernetes builtin schema validator. A valid policy passes clean; a
// defaultAction outside the enum is rejected, naming the offending field.
func TestWAFPolicySchemaValidationApplyParse(t *testing.T) {
	crd := loadCommittedCRD(t)
	if crd.Spec.Validation == nil || crd.Spec.Validation.OpenAPIV3Schema == nil {
		t.Fatalf("internal CRD lost the structural schema through conversion")
	}
	schemaValidator, _, err := validation.NewSchemaValidator(crd.Spec.Validation.OpenAPIV3Schema)
	if err != nil {
		t.Fatalf("build schema validator: %v", err)
	}

	if errs := validation.ValidateCustomResource(nil, unstructured(t, wafPolicyYAML), schemaValidator); len(errs) != 0 {
		t.Errorf("valid fixture rejected by the CRD schema: %v", errs.ToAggregate())
	}

	invalidYAML := strings.Replace(wafPolicyYAML, "defaultAction: block", "defaultAction: drop", 1)
	if invalidYAML == wafPolicyYAML {
		t.Fatal("self-test failed: the invalid-fixture rewrite was a no-op")
	}
	errs := validation.ValidateCustomResource(nil, unstructured(t, invalidYAML), schemaValidator)
	if len(errs) == 0 {
		t.Fatalf("defaultAction %q accepted: enum validation missing", "drop")
	}
	named := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "defaultAction") {
			named = true
			break
		}
	}
	if !named {
		t.Errorf("enum rejection does not name defaultAction: %v", errs.ToAggregate())
	}
}

// unstructured decodes a manifest the way the apiserver receives an apply:
// a plain map, no typed reflection.
func unstructured(t *testing.T, manifestYAML string) map[string]interface{} {
	t.Helper()
	var obj map[string]interface{}
	if err := yaml.Unmarshal([]byte(manifestYAML), &obj); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	return obj
}

// loadCommittedCRD reads the generated CRD manifest and returns it in the
// internal form the validation package consumes (the v1 manifest converts
// through a scheme carrying both apiextensions forms — the conversion path
// the apiserver applies to served CRDs).
func loadCommittedCRD(t *testing.T) *apiextensions.CustomResourceDefinition {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(moduleRoot(t), filepath.FromSlash(generatedCRDPath)))
	if err != nil {
		t.Fatalf("read committed %s: %v", generatedCRDPath, err)
	}
	var crdv1 apiextensionsv1.CustomResourceDefinition
	if err := yaml.Unmarshal(raw, &crdv1); err != nil {
		t.Fatalf("unmarshal CRD manifest: %v", err)
	}
	if crdv1.Spec.Group != GroupName {
		t.Fatalf("CRD group: got %q, want %q", crdv1.Spec.Group, GroupName)
	}
	if len(crdv1.Spec.Versions) == 0 || crdv1.Spec.Versions[0].Schema == nil || crdv1.Spec.Versions[0].Schema.OpenAPIV3Schema == nil {
		t.Fatalf("CRD carries no v1alpha1 schema")
	}
	scheme := runtime.NewScheme()
	if err := apiextensions.AddToScheme(scheme); err != nil {
		t.Fatalf("register internal apiextensions: %v", err)
	}
	if err := apiextensionsv1.AddToScheme(scheme); err != nil {
		t.Fatalf("register v1 apiextensions: %v", err)
	}
	crd := &apiextensions.CustomResourceDefinition{}
	if err := scheme.Convert(&crdv1, crd, nil); err != nil {
		t.Fatalf("convert CRD v1 to internal: %v", err)
	}
	return crd
}

// generateCRD runs the pinned controller-gen into scratch and returns the
// generated trishula.security_wafpolicies.yaml bytes. The rename step
// (generated filename → committed artifact name) is the only difference
// between the run output and the versioned path.
func generateCRD(t *testing.T, scratch string) []byte {
	t.Helper()
	const generatedName = "trishula.security_wafpolicies.yaml"
	cmd := exec.Command("go", "run",
		"sigs.k8s.io/controller-tools/cmd/controller-gen@"+controllerGenVersion,
		"crd",
		"paths=./api/v1alpha1",
		"output:crd:artifacts:config="+scratch)
	cmd.Dir = moduleRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("controller-gen %s: %v\n%s", controllerGenVersion, err, out)
	}
	raw, err := os.ReadFile(filepath.Join(scratch, generatedName))
	if err != nil {
		t.Fatalf("read generated CRD: %v", err)
	}
	return raw
}

// moduleRoot locates the clone root (the controller-gen invocation and the
// committed-manifest path are module-root relative; tests run in the
// package directory).
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("go.mod not found above %s", dir)
		}
		dir = parent
	}
}

// firstDiff returns the first byte index where a and b diverge.
func firstDiff(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// showByte renders an off-by-one byte window for divergence messages.
func showByte(b []byte, i int) string {
	if i < 0 {
		i = 0
	}
	if i >= len(b) {
		return "<end>"
	}
	lo, hi := i-8, i+8
	if lo < 0 {
		lo = 0
	}
	if hi > len(b) {
		hi = len(b)
	}
	return string(b[lo:hi])
}
