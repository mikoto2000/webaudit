package audit

import (
	"fmt"
	"testing"
)

// Isolate final aggregation from per-request parsing and online baselines.
func BenchmarkAnalysisFinishPeers(b *testing.B) {
	for _, n := range []int{128, 1024, 4096} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			a := NewAnalysis(Options{})
			for i := 0; i < n; i++ {
				a.ips[fmt.Sprint(i)] = &peer{n: 25, statusN: 25, bytesN: 25, bytes: float64(2500 + i%31), errors: int64(i % 5)}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				a.Finish()
			}
		})
	}
}
