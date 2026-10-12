package utils

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileLogger 文件日志管理器
type FileLogger struct {
	logDir     string
	currentDay string
	file       *os.File
	mutex      sync.Mutex
}

// NewFileLogger 创建文件日志管理器
func NewFileLogger(logDir string) (*FileLogger, error) {
	// 确保日志目录存在
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	logger := &FileLogger{
		logDir: logDir,
	}

	// 打开当前日志文件
	if err := logger.openLogFile(); err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	return logger, nil
}

// openLogFile 打开当前日期的日志文件
func (fl *FileLogger) openLogFile() error {
	// 获取当前日期
	currentDay := time.Now().Format("2006-01-02")

	// 如果是同一天且文件已打开，直接返回
	if fl.currentDay == currentDay && fl.file != nil {
		return nil
	}

	// 关闭旧文件
	if fl.file != nil {
		fl.file.Close()
	}

	// 构造新文件名
	filename := filepath.Join(fl.logDir, fmt.Sprintf("dns-proxy-%s.log", currentDay))

	// 打开文件（追加模式）
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file %s: %w", filename, err)
	}

	fl.currentDay = currentDay
	fl.file = file
	return nil
}

// Write 写入日志
func (fl *FileLogger) Write(p []byte) (n int, err error) {
	fl.mutex.Lock()
	defer fl.mutex.Unlock()

	// 检查是否需要切换到新文件
	if err := fl.openLogFile(); err != nil {
		return 0, err
	}

	// 写入日志
	return fl.file.Write(p)
}

// Close 关闭日志文件
func (fl *FileLogger) Close() error {
	fl.mutex.Lock()
	defer fl.mutex.Unlock()

	if fl.file != nil {
		return fl.file.Close()
	}
	return nil
}

// GetLogFilePath 获取当前日志文件路径
func (fl *FileLogger) GetLogFilePath() string {
	fl.mutex.Lock()
	defer fl.mutex.Unlock()

	if fl.currentDay != "" {
		return filepath.Join(fl.logDir, fmt.Sprintf("dns-proxy-%s.log", fl.currentDay))
	}
	return ""
}

// CleanupOldLogs 删除超过保留天数的历史日志文件（dns-proxy-YYYY-MM-DD.log）。
// 保留天数按自然日计算：文件名里的日期早于 (今天-保留天数) 的文件都会被删除，
// 当天文件无论大小都保留（由上层控制写盘量）。
func (fl *FileLogger) CleanupOldLogs(retentionDays int) error {
	if retentionDays <= 0 {
		retentionDays = 7
	}
	cutoff := time.Now().AddDate(0, 0, -retentionDays).Format("2006-01-02")
	pattern := filepath.Join(fl.logDir, "dns-proxy-*.log")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return err
	}
	removed := 0
	for _, path := range matches {
		base := filepath.Base(path) // dns-proxy-2026-10-01.log
		if len(base) < len("dns-proxy-")+len("2006-01-02") {
			continue
		}
		day := base[len("dns-proxy-") : len("dns-proxy-")+10]
		if _, err := time.Parse("2006-01-02", day); err != nil {
			continue // 非标准日期命名，跳过
		}
		if day < cutoff {
			if err := os.Remove(path); err == nil {
				removed++
			}
		}
	}
	if removed > 0 {
		log.Printf("[FileLogger] 清理过期日志: 保留 %d 天，删除 %d 个文件", retentionDays, removed)
	}
	return nil
}
