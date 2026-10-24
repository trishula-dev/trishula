package dx1

import (
	crd "github.com/trishula-dev/trishula/cue/crd"
	k8s "github.com/trishula-dev/trishula/cue/k8s"
)

// Package dx1 (cue/lab/dx1) owns the DX1 lab's Kubernetes manifests
// (TR-46, issue #192, census row "Lab k8s manifests" — CUE-owned).
// internal/cuegen derives every file into deployment/dx1/manifests/; the
// lab scripts apply from that tree (lab/dx1/setup.sh, apply-effect.sh). A
// change to a manifest is a change here, never in the derived files.
//
// The WAFPolicy CRs of this package validate against cue/crd.#WAFPolicySpec
// — the same CUE-layer schema the committed CRD is vetted against — so the
// lab manifests and the CRD cannot drift apart silently.

// File is one derived manifest file: the comment header (provenance + the
// TR/issue record the manifest carries) and the object list.
#File: {
	header: string
	objects: [...#AnyObject]
}

// AnyObject is one object shape the lab manifests carry: the Kubernetes
// kinds of cue/k8s plus the trishula.security WAFPolicy CR of cue/crd.
#AnyObject: k8s.#AnyObject | crd.#WAFPolicy

//
// The manifest files. Each entry keys the derived file name under
// deployment/dx1/manifests/.
files: [string]: #File
