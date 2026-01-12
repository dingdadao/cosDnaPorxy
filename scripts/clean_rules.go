package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

var (
	ruleFiles = []struct {
		Name string
		URL  string
	}{
		{"WeChat", "https://raw.githubusercontent.com/Thoseyearsbrian/Aegis/refs/heads/main/rules/WeChat.list"},
		{"Apple", "https://raw.githubusercontent.com/Thoseyearsbrian/Aegis/refs/heads/main/rules/Apple.list"},
		{"Telegram", "https://raw.githubusercontent.com/Thoseyearsbrian/Aegis/refs/heads/main/rules/Telegram.list"},
		{"ChinaMedia", "https://raw.githubusercontent.com/Thoseyearsbrian/Aegis/refs/heads/main/rules/ChinaMedia.list"},
	}

	outputDir = "shell/rules"
)

func main() {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Printf("创建输出目录失败: %v\n", err)
		return
	}

	for _, rf := range ruleFiles {
		fmt.Printf("处理: %s ...\n", rf.Name)

		content, err := download(rf.URL)
		if err != nil {
			fmt.Printf("  下载失败: %v\n", err)
			continue
		}

		yamlContent := convertToYAML(content, rf.Name)

		outputPath := filepath.Join(outputDir, rf.Name+".yaml")
		if err := os.WriteFile(outputPath, []byte(yamlContent), 0644); err != nil {
			fmt.Printf("  保存失败: %v\n", err)
			continue
		}

		fmt.Printf("  已保存: %s (已彻底清理尾部非标准注释)\n", outputPath)
	}

	fmt.Println("\n转换完成！现在所有 IP-CIDR 规则都是纯净格式，不会再报 payloadRule error")
}

func download(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func convertToYAML(raw string, title string) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# %s.yaml - Aegis 纯净转换版\n", title))
	sb.WriteString(fmt.Sprintf("# 来源: %s\n", ruleFiles[findIndex(title)].URL))
	sb.WriteString("# 说明: 自动补 IPv4 /32，已强制移除所有规则尾部注释/描述（包括中文无#描述）\n\n")
	sb.WriteString("payload:\n")

	scanner := bufio.NewScanner(strings.NewReader(raw))

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), " \t\r")

		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "#") {
			sb.WriteString(line + "\n")
			continue
		}

		// 强制清理：从第一个空格开始截断（处理无#的尾部中文描述）
		parts := strings.SplitN(line, " ", 2)
		cleaned := strings.TrimSpace(parts[0])

		if cleaned == "" {
			continue
		}

		// 自动补 /32 for IPv4 IP-CIDR
		if strings.HasPrefix(cleaned, "IP-CIDR,") {
			ipPart := strings.TrimPrefix(cleaned, "IP-CIDR,")
			if !strings.Contains(ipPart, "/") {
				ip := ipPart
				if net.ParseIP(ip) != nil && !strings.Contains(ip, ":") {
					cleaned = fmt.Sprintf("IP-CIDR,%s/32", ip)
				}
			}
		}

		sb.WriteString("  - " + cleaned + "\n")
	}

	return sb.String()
}

func findIndex(name string) int {
	for i, rf := range ruleFiles {
		if rf.Name == name {
			return i
		}
	}
	return 0
}
