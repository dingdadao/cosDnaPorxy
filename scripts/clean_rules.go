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
	// 要处理的规则文件列表
	ruleFiles = []struct {
		Name string
		URL  string
	}{
		{"WeChat", "https://raw.githubusercontent.com/Thoseyearsbrian/Aegis/refs/heads/main/rules/WeChat.list"},
		{"Apple", "https://raw.githubusercontent.com/Thoseyearsbrian/Aegis/refs/heads/main/rules/Apple.list"},
		{"Telegram", "https://raw.githubusercontent.com/Thoseyearsbrian/Aegis/refs/heads/main/rules/Telegram.list"},
		{"ChinaMedia", "https://raw.githubusercontent.com/Thoseyearsbrian/Aegis/refs/heads/main/rules/ChinaMedia.list"},
		{"OpenAI", "https://raw.githubusercontent.com/Thoseyearsbrian/Aegis/refs/heads/main/rules/OpenAI.list"},
	}

	outputDir = "shell/rules"
)

func main() {
	// 创建输出目录
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Printf("创建输出目录失败: %v\n", err)
		return
	}

	for _, rf := range ruleFiles {
		fmt.Printf("处理: %s ...\n", rf.Name)

		// 下载文件内容
		content, err := download(rf.URL)
		if err != nil {
			fmt.Printf("  下载失败: %v\n", err)
			continue
		}

		// 清理并转换为 YAML
		yamlContent := convertToYAML(content, rf.Name)

		// 保存到文件
		outputPath := filepath.Join(outputDir, rf.Name+".yaml")
		if err := os.WriteFile(outputPath, []byte(yamlContent), 0644); err != nil {
			fmt.Printf("  保存失败: %v\n", err)
			continue
		}

		fmt.Printf("  已保存: %s\n", outputPath)
	}

	fmt.Println("\n全部转换完成！")
	fmt.Printf("输出目录: %s\n", filepath.Join(".", outputDir))
	fmt.Println("可在 Mihomo 中使用 type: file + format: yaml + behavior: classical")
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

	sb.WriteString(fmt.Sprintf("# %s.yaml - 从 Aegis 转换\n", title))
	sb.WriteString(fmt.Sprintf("# 来源: %s\n", ruleFiles[findIndex(title)].URL))
	sb.WriteString("# 转换时间: 自动生成\n\n")
	sb.WriteString("payload:\n")

	scanner := bufio.NewScanner(strings.NewReader(raw))
	commentRe := regexp.MustCompile(`\s*#.*$`) // 匹配行尾注释

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), " \t")

		if line == "" {
			sb.WriteString("\n")
			continue
		}

		if strings.HasPrefix(line, "#") {
			// 保留整行注释（YAML 注释用 #）
			sb.WriteString(line + "\n")
			continue
		}

		// 移除行尾注释
		cleaned := commentRe.ReplaceAllString(line, "")
		cleaned = strings.TrimSpace(cleaned)

		if cleaned == "" {
			continue // 整行其实是注释但没以#开头，跳过
		}

		// 输出为 YAML 列表项
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
