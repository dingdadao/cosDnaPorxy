package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"
)

// LogLevel 日志级别
type LogLevel int

const (
	LogDebug LogLevel = iota
	LogInfo
	LogWarn
	LogError
)

// LogEntry 结构化日志条目
type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Component string                 `json:"component"`
	Function  string                 `json:"function"`
	Line      int                    `json:"line"`
	File      string                 `json:"file"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
	Duration  string                 `json:"duration,omitempty"`
}

// EnhancedLogger 增强的结构化日志器
type EnhancedLogger struct {
	level      LogLevel
	component  string
	useJSON    bool
	fileLogger *FileLogger
}

// NewEnhancedLogger 创建增强日志器
func NewEnhancedLogger(levelStr, component string, useJSON bool) *EnhancedLogger {
	level := LogInfo
	switch levelStr {
	case "debug":
		level = LogDebug
	case "info":
		level = LogInfo
	case "warn":
		level = LogWarn
	case "error":
		level = LogError
	}

	// 创建文件日志管理器
	fileLogger, err := NewFileLogger("./logs")
	if err != nil {
		// 如果创建文件日志失败，继续使用标准日志
		log.Printf("Warning: failed to create file logger: %v", err)
	}

	logger := &EnhancedLogger{
		level:      level,
		component:  component,
		useJSON:    useJSON,
		fileLogger: fileLogger,
	}

	// 如果文件日志管理器创建成功，设置日志输出到文件
	if fileLogger != nil {
		log.SetOutput(&logMultiWriter{stdout: os.Stdout, fileLogger: fileLogger})
	}

	return logger
}

// logMultiWriter 多输出写入器
type logMultiWriter struct {
	stdout     *os.File
	fileLogger *FileLogger
}

// Write 实现io.Writer接口
func (mw *logMultiWriter) Write(p []byte) (n int, err error) {
	// 写入标准输出
	stdoutN, stdoutErr := mw.stdout.Write(p)

	// 写入文件日志
	fileN, fileErr := mw.fileLogger.Write(p)

	// 返回较大的写入字节数和可能的错误
	if stdoutErr != nil {
		return stdoutN, stdoutErr
	}
	if fileErr != nil {
		return fileN, fileErr
	}

	return max(stdoutN, fileN), nil
}

// max 返回两个整数中的较大值
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// getCallerInfo 获取调用者信息
func (l *EnhancedLogger) getCallerInfo() (string, string, int) {
	pc, file, line, ok := runtime.Caller(3)
	if !ok {
		return "unknown", "unknown", 0
	}

	function := runtime.FuncForPC(pc).Name()
	return function, file, line
}

// log 通用日志方法
func (l *EnhancedLogger) log(level LogLevel, message string, fields map[string]interface{}, duration *time.Duration) {
	if level < l.level {
		return
	}

	function, file, line := l.getCallerInfo()

	entry := LogEntry{
		Timestamp: time.Now().Format(time.RFC3339Nano),
		Level:     l.levelToString(level),
		Message:   message,
		Component: l.component,
		Function:  function,
		File:      file,
		Line:      line,
		Fields:    fields,
	}

	if duration != nil {
		entry.Duration = duration.String()
	}

	if l.useJSON {
		jsonData, _ := json.Marshal(entry)
		log.Println(string(jsonData))
	} else {
		prefix := fmt.Sprintf("[%s][%s][%s:%d]", entry.Level, l.component, function, line)
		if duration != nil {
			prefix += fmt.Sprintf("[%s]", duration.String())
		}

		if len(fields) > 0 {
			fieldsStr, _ := json.Marshal(fields)
			log.Printf("%s %s %s", prefix, message, string(fieldsStr))
		} else {
			log.Printf("%s %s", prefix, message)
		}
	}
}

// levelToString 转换日志级别
func (l *EnhancedLogger) levelToString(level LogLevel) string {
	switch level {
	case LogDebug:
		return "DEBUG"
	case LogInfo:
		return "INFO"
	case LogWarn:
		return "WARN"
	case LogError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// Debug 调试日志
func (l *EnhancedLogger) Debug(message string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(LogDebug, message, f, nil)
}

// Info 信息日志
func (l *EnhancedLogger) Info(message string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(LogInfo, message, f, nil)
}

// Warn 警告日志
func (l *EnhancedLogger) Warn(message string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(LogWarn, message, f, nil)
}

// Error 错误日志
func (l *EnhancedLogger) Error(message string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(LogError, message, f, nil)
}

// WithDuration 带耗时的日志
func (l *EnhancedLogger) WithDuration(level LogLevel, message string, duration time.Duration, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(level, message, f, &duration)
}

// PerformanceTimer 性能计时器
type PerformanceTimer struct {
	logger    *EnhancedLogger
	operation string
	startTime time.Time
	fields    map[string]interface{}
}

// StartTimer 开始计时
func (l *EnhancedLogger) StartTimer(operation string, fields ...map[string]interface{}) *PerformanceTimer {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}

	return &PerformanceTimer{
		logger:    l,
		operation: operation,
		startTime: time.Now(),
		fields:    f,
	}
}

// End 结束计时并记录
func (pt *PerformanceTimer) End() time.Duration {
	duration := time.Since(pt.startTime)
	pt.logger.WithDuration(LogInfo, fmt.Sprintf("⏱️ %s completed", pt.operation), duration, pt.fields)
	return duration
}

// EndWithError 结束计时并记录错误
func (pt *PerformanceTimer) EndWithError(err error) time.Duration {
	duration := time.Since(pt.startTime)
	if pt.fields == nil {
		pt.fields = make(map[string]interface{})
	}
	pt.fields["error"] = err.Error()
	pt.logger.WithDuration(LogError, fmt.Sprintf("❌ %s failed", pt.operation), duration, pt.fields)
	return duration
}
