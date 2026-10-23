// cmd/operator — trishula-operator v0 (TR-08c, issue #76, the spec's architecture): a thin
// watch loop over WAFPolicy CRs. On every event (and a resync tick) it
// reconciles the namespace's policies (internal/operator.Reconcile:
// rule-pack resolution + compile, fail closed) and publishes the compiled
// bundle where the engine's --bundle leg picks it up — a ConfigMap in the
// policy's namespace. The publish slot is per tenant: each bundle lands in
// its policy's namespace, so tenants never share one ConfigMap and one
// tenant's rules never overwrite another's (the spec's multi-tenancy requirement R8, TR-25).
//
// Fail closed (the spec's architecture plus its precedence rule): an uncompilable/unresolvable policy logs its
// compile error and publishes NO bundle — traffic keeps its previous shape,
// the operator never crashes on it (Reconcile's error outcomes), and the
// watch loop keeps reconciling (a later CR fix heals without a restart).
//
// Rule-pack source (v0): CEL rule packs ride ConfigMaps named by the
// policy's RuleSetRef in the policy's namespace (data key pack.yaml) — the
// The spec's RuleSet object's content half, stubbed at ConfigMap granularity.
// Unresolved refs fail the policy's compile.
//
// Deliberately NOT here yet (later TR-08 slices): informer caches, work
// queues, leader election, status Conditions — the loop lists+watches via
// the client-go dynamic client (one List + one Watch; client-go only).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"

	"github.com/trishula-dev/trishula/api/v1alpha1"
	"github.com/trishula-dev/trishula/internal/engine/cel"
	"github.com/trishula-dev/trishula/internal/operator"
)

// bundleCMName is the ConfigMap the compiled bundle lands in (data key
// bundle.json); the engine's --bundle pickup reads it.
const bundleCMName = "dx1-wafpolicy-bundle"

// serveHealthz answers readiness on :1936 (the pod's probe port; the
// kubelet probes the pod IP, so the listener is not loopback-only). Runs
// for the process lifetime; the reconcile loop's health is the pod being
// Ready.
func serveHealthz() {
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("ok"))
		})
		if err := http.ListenAndServe(":1936", mux); err != nil {
			log.Printf("operator: healthz endpoint: %v", err)
		}
	}()
}

// gvr is the WAFPolicy REST mapping (v1alpha1); configmapsGVR the
// ConfigMap one (the v0 transports).
var gvr = schema.GroupVersionResource{
	Group:    v1alpha1.GroupVersion.Group,
	Version:  v1alpha1.GroupVersion.Version,
	Resource: "wafpolicies",
}

var configMapsGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}

// cmSource is the v0 RulePackSource over ConfigMaps in the policy's
// namespace (data key pack.yaml; the name is the RuleSetRef's).
type cmSource struct{ dc dynamic.Interface }

func (s cmSource) RulePack(ctx context.Context, ns, name string) (cel.RulePack, bool, error) {
	cm, err := s.dc.Resource(configMapsGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return cel.RulePack{}, false, nil
	}
	if err != nil {
		return cel.RulePack{}, false, err
	}
	data, ok := cm.UnstructuredContent()["data"].(map[string]any)["pack.yaml"].(string)
	if !ok {
		return cel.RulePack{}, false, fmt.Errorf("configmap %s/%s carries no pack.yaml", ns, name)
	}
	pack, err := cel.ParseRulePack([]byte(data))
	if err != nil {
		return cel.RulePack{}, false, fmt.Errorf("configmap %s/%s: %w", ns, name, err)
	}
	return *pack, true, nil
}

// listPolicies lists every WAFPolicy in ns ("" = all namespaces) into typed
// objects (the dynamic client decodes through the v1alpha1 scheme).
func listPolicies(ctx context.Context, dc dynamic.Interface, ns string) ([]v1alpha1.WAFPolicy, error) {
	u, err := dc.Resource(gvr).Namespace(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	items := make([]v1alpha1.WAFPolicy, 0, len(u.Items))
	for i := range u.Items {
		var p v1alpha1.WAFPolicy
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Items[i].Object, &p); err != nil {
			return nil, err
		}
		items = append(items, p)
	}
	return items, nil
}

// watchPolicies watches WAFPolicy events (an event nudges the reconcile;
// the resync tick below is the safety net for missed events).
func watchPolicies(ctx context.Context, dc dynamic.Interface, ns string) (watch.Interface, error) {
	return dc.Resource(gvr).Namespace(ns).Watch(ctx, metav1.ListOptions{})
}

// publishBundle lands the compiled bundle in the bundle ConfigMap of the
// POLICY's namespace (data key bundle.json) — the per-tenant publish slot
// (the spec's multi-tenancy requirement R8); the pickup the lab's engine polls.
func publishBundle(ctx context.Context, dc dynamic.Interface, ns string, o operator.Outcome) error {
	data, err := json.Marshal(o.Bundle)
	if err != nil {
		return err
	}
	cms := dc.Resource(configMapsGVR).Namespace(ns)
	existing, err := cms.Get(ctx, bundleCMName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		cm := &unstructured.Unstructured{}
		cm.SetGroupVersionKind(schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"})
		cm.SetName(bundleCMName)
		cm.SetNamespace(ns)
		cm.UnstructuredContent()["data"] = map[string]any{"bundle.json": string(data)}
		_, err = cms.Create(ctx, cm, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	existing.UnstructuredContent()["data"] = map[string]any{"bundle.json": string(data)}
	_, err = cms.Update(ctx, existing, metav1.UpdateOptions{})
	return err
}

// markAnnotated stamps an annotation on the policy — the operator's applied
// evidence (v0: one observation; Conditions ride a later TR-08 slice).
func markAnnotated(ctx context.Context, dc dynamic.Interface, ns, name string) {
	_ = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		u, err := dc.Resource(gvr).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		u.SetAnnotations(map[string]string{"trishula.security/compiled": "true"})
		_, err = dc.Resource(gvr).Namespace(ns).Patch(ctx, u.GetName(), types.MergePatchType,
			[]byte(`{"metadata":{"annotations":{"trishula.security/compiled":"true"}}}`), metav1.PatchOptions{})
		return err
	})
}

func main() {
	kubeconfig := flag.String("kubeconfig", "", "kubeconfig path (default: env/in-cluster)")
	watchNS := flag.String("namespace", "dx1", "namespace whose WAFPolicies reconcile (\"\": all)")
	resync := flag.Duration("resync", 250*time.Millisecond, "reconcile tick (the M9 pickup budget)")
	flag.Parse()

	cfg, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		log.Fatalf("operator: kubeconfig: %v", err)
	}
	dc, err := dynamic.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("operator: dynamic client: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serveHealthz()

	reconcileOnce := func() {
		policies, err := listPolicies(ctx, dc, *watchNS)
		if err != nil {
			log.Printf("operator: list wafpolicies: %v", err)
			return
		}
		for _, o := range operator.Reconcile(ctx, policies, cmSource{dc}) {
			if o.Err != nil {
				// Fail closed: the error outcome ships no bundle; the log
				// line is the operator-side M9 failure evidence.
				log.Printf("operator: COMPILE FAILED %s: %v (no bundle published — fail closed)", o.Key, o.Err)
				continue
			}
			// Per-tenant publish slot (the spec's multi-tenancy requirement R8): the bundle lands in
			// the policy's own namespace, never a shared slot.
			pubNS, _, ok := splitKey(o.Key)
			if !ok {
				log.Printf("operator: outcome key %q splits to no namespace (no publish)", o.Key)
				continue
			}
			if err := publishBundle(ctx, dc, pubNS, o); err != nil {
				log.Printf("operator: publish %s: %v", o.Key, err)
				continue
			}
			log.Printf("operator: compiled %s → %s/%s (bundle.json, tenant publish)", o.Key, pubNS, bundleCMName)
			if ns, name, ok := splitKey(o.Key); ok {
				markAnnotated(ctx, dc, ns, name)
			}
		}
	}

	reconcileOnce()
	w, err := watchPolicies(ctx, dc, *watchNS)
	if err != nil {
		log.Fatalf("operator: watch wafpolicies: %v", err)
	}
	defer w.Stop()
	tick := time.NewTicker(*resync)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("operator: shutting down")
			return
		case <-w.ResultChan():
			reconcileOnce()
		case <-tick.C:
			reconcileOnce()
		}
	}
}

// splitKey splits "<namespace>/<name>" (the Outcome.Key shape).
func splitKey(key string) (ns, name string, ok bool) {
	for i := 0; i < len(key); i++ {
		if key[i] == '/' {
			return key[:i], key[i+1:], true
		}
	}
	return "", "", false
}
