package config

import "testing"

// ECS 解析：只有开关打开 + 类型在白名单 + 地址可解析时才注入
func TestECSPolicyResolve(t *testing.T) {
	cases := []struct {
		name   string
		policy ECSPolicy
		want   string // 期望的 netip.Prefix 字符串；空串表示不注入
	}{
		{"关闭时不注入", ECSPolicy{Enabled: false, ISPType: ECSTypeTelecom, Subnet: "1.2.3.4"}, ""},
		{"类型不在白名单不注入", ECSPolicy{Enabled: true, ISPType: "cernet", Subnet: "1.2.3.4"}, ""},
		{"类型为空不注入", ECSPolicy{Enabled: true, ISPType: "", Subnet: "1.2.3.4"}, ""},
		{"地址为空不注入", ECSPolicy{Enabled: true, ISPType: ECSTypeTelecom, Subnet: "  "}, ""},
		{"地址非法不注入", ECSPolicy{Enabled: true, ISPType: ECSTypeTelecom, Subnet: "1.2.3.999"}, ""},
		{"CIDR 非法不注入", ECSPolicy{Enabled: true, ISPType: ECSTypeTelecom, Subnet: "1.2.3.0/33"}, ""},
		{"IPv4 裸 IP 按 /24", ECSPolicy{Enabled: true, ISPType: ECSTypeTelecom, Subnet: "1.2.3.4"}, "1.2.3.0/24"},
		{"IPv4 CIDR 取前缀", ECSPolicy{Enabled: true, ISPType: ECSTypeUnicom, Subnet: "1.2.3.4/16"}, "1.2.0.0/16"},
		{"IPv6 裸 IP 按 /56", ECSPolicy{Enabled: true, ISPType: ECSTypeMobile, Subnet: "240e:1:2:3:4:5:6:7"}, "240e:1:2::/56"},
		{"IPv6 CIDR 取前缀", ECSPolicy{Enabled: true, ISPType: ECSTypeMobile, Subnet: "240e:1:2::/32"}, "240e:1::/32"},
		{"首尾空白可容忍", ECSPolicy{Enabled: true, ISPType: ECSTypeTelecom, Subnet: " 1.2.3.0/24 "}, "1.2.3.0/24"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := c.policy.Resolve()
			if c.want == "" {
				if ok {
					t.Errorf("不应注入，实际得到 %v", got)
				}
				return
			}
			if !ok {
				t.Fatalf("应注入 %s，实际未注入", c.want)
			}
			if got.String() != c.want {
				t.Errorf("前缀应为 %s，实际 %s", c.want, got)
			}
		})
	}
}
