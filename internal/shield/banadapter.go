package shield

// TR-10 (issue #10) adapter — RED stub.
//
// BanEnforcer closes the enforcement loop: a rateban would-ban (the
// engine's Assess() record) is converted to a kernel bans_v4 write at the
// kernel clock (publish) and echoed to the evidence stream (§13.5: verdict
// "ban" once the kernel state exists; publish failures are failures of the
// ban, evidenced). Expiry auto-lift reconciles the kernel table with the
// engine's expiry semantics (now >= until ⇒ delete).
type BanEnforcer struct{}

// NewBanEnforcer builds an enforcer over a bans_v4 publisher + evidence
// sink. RED stub.
func NewBanEnforcer(pub MapPublisher, sink *JSONLEvidenceSink) *BanEnforcer {
	panic("TR-10 GREEN pending: NewBanEnforcer")
}

// MapPublisher is the bans_v4 write surface (kernel maps or a test stub).
type MapPublisher interface{}

// Record converts and publishes one would-ban. RED stub.
func (b *BanEnforcer) Record(r BanRecord) error { panic("TR-10 GREEN pending: Record") }

// Reconcile deletes expired bans. RED stub.
func (b *BanEnforcer) Reconcile(nowMs int64) int { panic("TR-10 GREEN pending: Reconcile") }
