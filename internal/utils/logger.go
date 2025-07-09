package utils

import "log"

// Logger 日志记录器
type Logger struct {
	level string
}

// NewLogger 创建新的日志记录器
func NewLogger(level string) *Logger {
	return &Logger{level: level}
}

// Debug 调试日志
func (l *Logger) Debug(format string, v ...interface{}) {
	if l.level == "debug" {
		log.Printf("[DEBUG] "+format, v...)
	}
}

// Info 信息日志
func (l *Logger) Info(format string, v ...interface{}) {
	log.Printf("[INFO] "+format, v...)
}

// Warn 警告日志
func (l *Logger) Warn(format string, v ...interface{}) {
	log.Printf("[WARN] "+format, v...)
}

// Error 错误日志
func (l *Logger) Error(format string, v ...interface{}) {
	log.Printf("[ERROR] "+format, v...)
} 