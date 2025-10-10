package utils

import (
	"cosDnaPorxy/internal/config"
	"fmt"
	"os"
	"path/filepath"
)

func InitResourceFiles(cfg *config.Config) error {
	dataDir := "data"
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			return fmt.Errorf("无法创建data目录: %w", err)
		}
		fmt.Println("已创建data目录")
	}

	for _, f := range []string{cfg.DesignatedDomain} {
		if f == "" {
			continue
		}
		if _, err := os.Stat(f); os.IsNotExist(err) {
			if err := os.MkdirAll(filepath.Dir(f), 0755); err != nil {
				fmt.Printf("无法创建目录: %v\n", err)
				continue
			}
			if file, err := os.Create(f); err != nil {
				fmt.Printf("无法创建文件 %s: %v\n", f, err)
			} else {
				file.Close()
				fmt.Printf("已创建空文件: %s\n", f)
			}
		} else {
			fmt.Printf("文件已存在: %s\n", f)
		}
	}

	return nil
}
