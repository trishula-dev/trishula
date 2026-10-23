package bench

// The `go test -bench` surface: the same recipes the CI guards measure,
// exposed as standard Go benchmarks for the benchstat-style comparison
// the baseline-regression CI leg runs on.
import "testing"

func benchmarkRecipe(b *testing.B, id string) {
	for _, rs := range recipesByScenario(b) {
		for _, r := range rs {
			if r.ID != id {
				continue
			}
			eval := reference(b)
			for i := 0; i < r.Warmup; i++ {
				_, _ = eval.Evaluate(BuildRequest(r))
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = eval.Evaluate(BuildRequest(r))
			}
			return
		}
	}
	b.Fatalf("recipe %q not in the recipe catalog", id)
}

func BenchmarkInlineIdle(b *testing.B)       { benchmarkRecipe(b, "idle-get") }
func BenchmarkInlineSteady8K(b *testing.B)   { benchmarkRecipe(b, "steady-json-8k") }
func BenchmarkBodyLadderForm8K(b *testing.B) { benchmarkRecipe(b, "ladder-form-dense-8k") }
