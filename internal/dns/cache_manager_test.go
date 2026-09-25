package dns

import (
	"os"
	"testing"
	"time"

	"cosDnaPorxy/internal/config"
	"cosDnaPorxy/internal/utils"

	"github.com/miekg/dns"
)

// newTestCacheManager 构造测试用缓存管理器
// logger构造会写./logs目录，chdir到临时目录避免污染仓库
func newTestCacheManager(t *testing.T) *CacheManager {
	t.Helper()
	origWd, _ := os.Getwd()
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir失败: %v", err)
	}
	t.Cleanup(func() { os.Chdir(origWd) })

	logger := utils.NewEnhancedLogger("error", "test", false)
	return NewCacheManager(config.DefaultConfig(), logger)
}

// TestCacheManagerCloseSafety 关闭安全性回归：
// 重复Close、关闭后提交任务都不得panic。
// 旧实现 Close() 中 close(cm.asyncChan) 会导致 worker 从已关闭channel读到nil任务，
// 在 processAsyncTask 空指针崩溃；对已关闭channel提交任务同样panic。
func TestCacheManagerCloseSafety(t *testing.T) {
	cm := newTestCacheManager(t)

	cm.Close()
	cm.Close() // 重复关闭必须安全

	cm.submitAsyncRefresh("close-test.example.com", dns.TypeA, time.Now().Add(time.Minute), 0)
	cm.submitOnDemandRefresh("close-test2.example.com", dns.TypeA)
}
