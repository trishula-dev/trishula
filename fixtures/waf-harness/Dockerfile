# fixtures/waf-harness — TR-205 (issue #289): one shared image recipe for the
# four harness images (engine, operator, vuln-app, benign-app). Each build
# passes one statically linked Go binary from the PR checkout; the image is
# a scratch root plus that binary. GOARCH must match the cluster node.
#
# The repo's lab image recipes use the same shape (lab/dx1/Dockerfile.engine,
# lab/dx1/Dockerfile.operator). The ko build is the registry-direct
# alternative; this harness builds in-job from the checkout (issue #289,
# item 2: no registry pull).
FROM scratch
ARG BIN
COPY "${BIN}" /app
ENTRYPOINT ["/app"]
