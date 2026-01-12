package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
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

		fmt.Printf("  已保存: %s\n", outputPath)
	}

	fmt.Println("\n全部转换完成！输出目录:", filepath.Join(".", outputDir))
	fmt.Println("现在 IP-CIDR 规则已自动补 /32，不会再报 payloadRule error")
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

	sb.WriteString(fmt.Sprintf("# %s.yaml - Aegis 转换版（自动补 IP-CIDR /32）\n", title))
	sb.WriteString(fmt.Sprintf("# 来源: %s\n", ruleFiles[findIndex(title)].URL))
	sb.WriteString("# 转换时间: 自动生成\n\n")
	sb.WriteString("payload:\n")

	scanner := bufio.NewScanner(strings.NewReader(raw))
	commentRe := regexp.MustCompile(`\s*#.*$`)                 // 移除行尾注释
	ipCidrRe := regexp.MustCompile(`^IP-CIDR,([\d.]+)(/.*)?$`) // 匹配 IPv4 IP-CIDR

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), " \t")

		if line == "" {
			sb.WriteString("\n")
			continue
		}

		if strings.HasPrefix(line, "#") {
			sb.WriteString(line + "\n")
			continue
		}

		// 移除行尾注释
		cleaned := commentRe.ReplaceAllString(line, "")
		cleaned = strings.TrimSpace(cleaned)

		if cleaned == "" {
			continue
		}

		// 自动补 /32 for IP-CIDR (IPv4)
		if match := ipCidrRe.FindStringSubmatch(cleaned); match != nil {
			ip := match[1]
			cidr := match[2]
			if cidr == "" {
				// 验证是有效 IPv4
				if net.ParseIP(ip) != nil {
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
