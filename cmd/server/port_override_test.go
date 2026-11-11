package main

import (
	"testing"

	"trail/internal/config"
)

func TestApplyPortOverride(t *testing.T) {
	cases := []struct {
		name     string
		flagPort int
		env      string
		want     int
		wantErr  bool
	}{
		{name: "no override keeps config port", flagPort: 0, env: "", want: 8080},
		{name: "flag wins", flagPort: 9090, env: "", want: 9090},
		{name: "env used when flag unset", flagPort: 0, env: "9100", want: 9100},
		{name: "flag wins over env", flagPort: 9090, env: "9100", want: 9090},
		{name: "env with spaces", flagPort: 0, env: "  9200  ", want: 9200},
		{name: "port 1 allowed", flagPort: 1, env: "", want: 1},
		{name: "port 65535 allowed", flagPort: 65535, env: "", want: 65535},
		{name: "port above range rejected", flagPort: 65536, env: "", wantErr: true},
		{name: "negative port rejected", flagPort: -1, env: "", wantErr: true},
		{name: "non numeric env rejected", flagPort: 0, env: "http", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CYBERSTRIKE_PORT", tc.env)
			cfg := &config.Config{}
			cfg.Server.Port = 8080

			err := applyPortOverride(cfg, tc.flagPort)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got none (port=%d)", cfg.Server.Port)
				}
				if cfg.Server.Port != 8080 {
					t.Fatalf("failed override must keep config port 8080, got %d", cfg.Server.Port)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.Server.Port != tc.want {
				t.Fatalf("port = %d, want %d", cfg.Server.Port, tc.want)
			}
		})
	}
}
