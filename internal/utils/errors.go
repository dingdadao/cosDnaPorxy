package utils

import "fmt"

// DNSError 自定义错误类型
type DNSError struct {
	Code    int
	Message string
	Err     error
}

// Error 实现error接口
func (e *DNSError) Error() string {
	return fmt.Sprintf("DNS error %d: %s (%v)", e.Code, e.Message, e.Err)
}

// NewDNSError 创建新的DNS错误
func NewDNSError(code int, message string, err error) *DNSError {
	return &DNSError{
		Code:    code,
		Message: message,
		Err:     err,
	}
} 