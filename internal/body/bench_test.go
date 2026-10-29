package body

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func largeHistory(turns int) []byte {
	var messages []map[string]any
	for i := range turns {
		var lines []string
		for j := range 120 {
			lines = append(lines, fmt.Sprintf("func handler%d_%d(w http.ResponseWriter) { log.Printf(\"user %%s\", \"client%d@mail-client.fr\") }", i, j, i*1000+j))
		}
		messages = append(messages,
			map[string]any{"role": "assistant", "content": []map[string]any{{"type": "tool_use", "id": fmt.Sprint("toolu_", i), "name": "Read", "input": map[string]string{"file_path": "/src/a.go"}}}},
			map[string]any{"role": "user", "content": []map[string]any{{"type": "tool_result", "tool_use_id": fmt.Sprint("toolu_", i), "content": strings.Join(lines, "\n")}}})
	}
	b, _ := json.Marshal(map[string]any{"model": "m", "messages": messages})
	return b
}

func BenchmarkMaskLargeHistory(b *testing.B) {
	body := largeHistory(80)
	b.ReportMetric(float64(len(body)>>10), "KiB")
	m := masker()
	MaskRequest(body, m)
	b.ResetTimer()
	for range b.N {
		MaskRequest(body, m)
	}
}

func BenchmarkMaskLargeHistoryCold(b *testing.B) {
	body := largeHistory(80)
	for range b.N {
		MaskRequest(body, masker())
	}
}
