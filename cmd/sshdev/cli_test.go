package main

import "testing"

func TestPinggyLocalPort(t *testing.T) {
	tests := []struct {
		name      string
		listen    string
		want      string
		wantError bool
	}{
		{
			name:   "完整 IPv4 地址",
			listen: "0.0.0.0:2222",
			want:   "2222",
		},
		{
			name:   "省略主机地址",
			listen: ":2222",
			want:   "2222",
		},
		{
			name:   "本机名称",
			listen: "localhost:2222",
			want:   "2222",
		},
		{
			name:   "IPv6 地址",
			listen: "[::1]:2222",
			want:   "2222",
		},
		{
			name:      "随机端口",
			listen:    "127.0.0.1:0",
			wantError: true,
		},
		{
			name:      "无效地址",
			listen:    "bad-address",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pinggyLocalPort(tt.listen)
			if tt.wantError {
				if err == nil {
					t.Fatalf("期望返回错误，实际成功得到 %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("期望成功，实际返回错误：%v", err)
			}
			if got != tt.want {
				t.Fatalf("端口不匹配：got %q, want %q", got, tt.want)
			}
		})
	}
}
