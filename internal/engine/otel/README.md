# internal/engine/otel — verdict observability pipeline (TR-11, PRD §15)

Three signals per request+verdict — span `trishula.verdict`, counter
`verdicts_total`, log record `trishula.verdict` — emitted in-process through
the OTel SDK and correlated by `request.id` on every signal (log carries
trace_id/span_id; the middleware adopts `X-Request-ID` or generates a
32-hex id). Correlation keys, attribute names and value shapes are pinned in
the package comment of `pipeline.go` — the collector deployment (TR-08c/TR-23)
reuses them verbatim; its config will need the otlphttp exporter, the three
receivers (trace/metric/log), and `service.name` from `Config.ServiceName`
as the resource value.
