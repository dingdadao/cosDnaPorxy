package main

import (
	"bufio"
	"fmt"
	"io"
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
		fmt.Printf("创建目录失败: %v\n", err)
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

	fmt.Println("\n转换完成！使用 type: file + format: yaml + behavior: classical")
}

func download(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
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

	sb.WriteString(fmt.Sprintf("# %s.yaml - Aegis 转换（修复 IP-CIDR / 尾随文本）\n", title))
	sb.WriteString(fmt.Sprintf("# 来源: %s\n", ruleFiles[findIndex(title)].URL))
	sb.WriteString("# 转换时间: 自动\n\n")
	sb.WriteString("payload:\n")

	scanner := bufio.NewScanner(strings.NewReader(raw))
	commentRe := regexp.MustCompile(`\s*#.*$`) // 移除行尾 #注释

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

		// 移除标准 #注释
		cleaned := commentRe.ReplaceAllString(line, "")

		// 处理无 # 但有尾随文本（如空格 + 中文）
		parts := regexp.MustCompile(`\s+`).Split(cleaned, -1)
		rulePart := parts[0] // 取第一个部分（规则）

		if !strings.Contains(rulePart, ",") {
			continue // 无效行
		}

		typVal := strings.SplitN(rulePart, ",", 2)
		if len(typVal) != 2 {
			continue
		}
		ruleType := strings.TrimSpace(typVal[0])
		value := strings.TrimSpace(typVal[1])

		// 自动补全 CIDR mask
		if (ruleType == "IP-CIDR" || ruleType == "IP-CIDR6") && !strings.Contains(value, "/") {
			if ruleType == "IP-CIDR" {
				value += "/32" // 单 IPv4 IP
			} else {
				value += "/128" // 单 IPv6 IP
			}
		}

		// 输出有效规则
		sb.WriteString(fmt.Sprintf("  - %s,%s\n", ruleType, value))
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
