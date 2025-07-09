package main

import (
	"cosDnaPorxy/internal/geosite"
	"fmt"
	"log"
)

func main() {
	// 创建Geosite管理器
	manager, err := geosite.NewManager("https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat", "72h")
	if err != nil {
		log.Fatalf("创建Geosite管理器失败: %v", err)
	}

	// 更新Geosite数据
	manager.UpdateGeoSite()

	// 测试域名列表
	testDomains := []string{
		"baidu.com",
		"qq.com",
		"taobao.com",
		"google.com",
		"facebook.com",
		"twitter.com",
		"youtube.com",
		"github.com",
	}

	fmt.Println("=== Geosite匹配测试 ===")
	fmt.Println("分组: GEOLOCATION-CN")
	fmt.Println()

	for _, domain := range testDomains {
		isCN := manager.CheckDomainInTag(domain, "GEOLOCATION-CN")
		status := "国外"
		if isCN {
			status = "国内"
		}
		fmt.Printf("%-15s -> %s\n", domain, status)
	}
} 