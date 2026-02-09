package loglog

import "testing"

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		name string
		in   int64
		want string
	}{
		{name: "bytes", in: 999, want: "999 B"},
		{name: "kilobytes", in: 1000, want: "1.0 kB"},
		{name: "megabytes", in: 1000 * 1000, want: "1.0 MB"},
		{name: "rounding", in: 1532, want: "1.5 kB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatBytes(tt.in); got != tt.want {
				t.Fatalf("formatBytes(%d) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
