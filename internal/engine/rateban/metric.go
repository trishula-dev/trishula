package rateban

import "sync/atomic"

// atomicRateTick increments the exported BanRateAboveBudget counter
// (TR-11's wiring point). Kept in its own tiny unit so the metric surface
// stays one visible line — this leaf has no exporter; TR-11 reads the
// counter.
func atomicRateTick() { atomic.AddInt64(BanRateAboveBudget, 1) }

// BanRateAboveBudgetValue reads the counter atomically (for tests and the
// TR-11 exporter; direct dereference is fine for single-word reads but
// this keeps the race-detector clean across packages).
func BanRateAboveBudgetValue() int64 { return atomic.LoadInt64(BanRateAboveBudget) }

// BanRateAboveBudgetTick increments the exported counter (the engine calls
// this once per would-ban; exported so TR-11 can backfill/replay or test
// wiring without emitting a synthetic evidence record).
func BanRateAboveBudgetTick() { atomic.AddInt64(BanRateAboveBudget, 1) }
