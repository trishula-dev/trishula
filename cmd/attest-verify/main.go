// Command attest-verify runs the TR-81 attestation verifier against a
// live release: it reads the GitHub release-assets surface, fetches the
// repository attestation store per asset digest, and reports one verdict
// per asset.
//
// The command is the structural gate. `gh attestation verify` holds the
// cryptographic step; run it per artifact as SECURITY.md records.
//
// Exit 0: every release asset carries both attestations. Exit 1: at least
// one asset rejects. Exit 2: a malformed call.
//
// PRD ref: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#181-assets-and-trust-boundaries
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/trishula-dev/trishula/internal/attest"
)

var apiBase = "https://api.github.com"

// ghClient reads the GitHub REST surfaces; the token is optional on a
// public repository.
type ghClient struct {
	repo  string
	token string
	hc    *http.Client
}

func (c ghClient) get(endpoint string) ([]byte, int, error) {
	req, err := http.NewRequest("GET", apiBase+endpoint, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("http get %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// lister reads the release-assets surface for one tag.
type lister struct{ ghClient }

func (l lister) Assets(tag string) ([]attest.AssetSpec, error) {
	body, status, err := l.get("/repos/" + l.repo + "/releases/tags/" + url.PathEscape(tag))
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("release-assets list returned status %d", status)
	}
	var doc struct {
		Assets []struct {
			Name   string `json:"name"`
			Digest string `json:"digest"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("release-assets decode: %w", err)
	}
	specs := make([]attest.AssetSpec, 0, len(doc.Assets))
	for _, a := range doc.Assets {
		specs = append(specs, attest.AssetSpec{Name: a.Name, SHA256: a.Digest})
	}
	return specs, nil
}

// fetcher reads the repository attestation store for one subject digest.
// The 404 response is absence, not a failure.
type fetcher struct {
	ghClient
}

func (f fetcher) Bundles(digest string) ([]attest.Bundle, error) {
	body, status, err := f.get("/repos/" + f.repo + "/attestations/" + url.PathEscape(digest))
	if err != nil {
		return nil, err
	}
	switch {
	case status == http.StatusNotFound:
		return nil, nil
	case status != http.StatusOK:
		return nil, fmt.Errorf("attestation store returned status %d", status)
	}
	var doc struct {
		Attestations []struct {
			Bundle json.RawMessage `json:"bundle"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("attestation store decode: %w", err)
	}
	bundles := make([]attest.Bundle, 0, len(doc.Attestations))
	for _, a := range doc.Attestations {
		bundles = append(bundles, attest.Bundle(a.Bundle))
	}
	return bundles, nil
}

func main() {
	repo := flag.String("repo", "trishula-dev/trishula", "owner/repository carrying the release")
	tag := flag.String("tag", "", "release tag to verify (required)")
	flag.Parse()
	if *tag == "" {
		fmt.Fprintln(os.Stderr, "usage: attest-verify -repo trishula-dev/trishula -tag 2026.01-rc2")
		os.Exit(2)
	}
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	client := ghClient{
		repo:  *repo,
		token: token,
		hc:    &http.Client{Timeout: 30 * time.Second},
	}
	v := &attest.Verifier{
		List:          lister{client},
		Fetch:         fetcher{client},
		BuilderPrefix: "https://github.com/" + *repo + "/",
	}
	results := v.Verify(*tag)
	fmt.Printf("TR-81 attest-verify: repo %s tag %s\n", *repo, *tag)
	pass := 0
	for _, r := range results {
		fmt.Printf("%-7s %s\n", r.Status, r.Asset.Name)
		for _, reason := range r.Reasons {
			fmt.Printf("         reason: %s\n", reason)
		}
		if r.Status == attest.StatusPass {
			pass++
		}
	}
	fmt.Printf("verdict: %d of %d assets carry both attestations\n", pass, len(results))
	if len(results) == 0 || pass != len(results) {
		os.Exit(1)
	}
}
