// Package source 提供客户端来源识别：运营商（ISP）标识。
//
// 结构设计：运营商 IP 段总量很小（常见实现约几千条 CIDR），因此用「二进制前缀树
// （binary trie）+ 最长前缀匹配」承载，查找深度只取决于 IP 位长（v4 ≤32、v6 ≤128），
// 与规则条数无关。IPv4/IPv6 各持一棵子树，兼容同一套运营商枚举。
//
// 并发模型：DB 内存有一份不可变快照，通过 atomic.Pointer 整体换新；读侧无锁，
// 后台重建后原子替换，不影响查询热路径。
package source

import (
	"net/netip"
	"strings"
	"sync/atomic"
)

// ISP 运营商标识
type ISP string

const (
	ISPTelecom  ISP = "telecom"  // 中国电信
	ISPUnicom   ISP = "unicom"   // 中国联通
	ISPCMCC     ISP = "cmcc"     // 中国移动（含铁通）
	ISPCernet   ISP = "cernet"   // 教育网
	ISPChinabtn ISP = "chinabtn" // 中国广电
	ISPGWBN     ISP = "gwbn"     // 鹏博士/长城宽带
	ISPOther    ISP = "other"    // 其他（兜底）
)

// KnownISPs 返回所有受支持的运营商
func KnownISPs() []ISP {
	return []ISP{ISPTelecom, ISPUnicom, ISPCMCC, ISPCernet, ISPChinabtn, ISPGWBN, ISPOther}
}

// ParseISP 解析运营商标识字符串，支持常见别名；未知返回 ok=false。
func ParseISP(s string) (ISP, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "telecom", "chinatelecom", "电信":
		return ISPTelecom, true
	case "unicom", "cnc", "cuc", "联通":
		return ISPUnicom, true
	case "cmcc", "mobile", "moving", "移动":
		return ISPCMCC, true
	case "cernet", "edunet", "教育":
		return ISPCernet, true
	case "chinabtn", "btn", "广电":
		return ISPChinabtn, true
	case "gwbn", "长宽", "鹏博士", "drpeng":
		return ISPGWBN, true
	case "other", "其他":
		return ISPOther, true
	}
	return "", false
}

// tnode 二进制前缀树节点
type tnode struct {
	isp  ISP    // 本节点对应前缀归属的运营商，空表示该前缀无归属
	zero *tnode // 下一位为 0
	one  *tnode // 下一位为 1
}

// binaryTrie 二进制前缀树
type binaryTrie struct {
	root *tnode
}

func newTrie() *binaryTrie {
	return &binaryTrie{root: &tnode{}}
}

// insert 插入前缀。bits 为原始地址字节，length 为前缀位数（v4 ≤32、v6 ≤128）。
func (t *binaryTrie) insert(bits []byte, length int, isp ISP) {
	n := t.root
	for i := 0; i < length; i++ {
		if bitAt(bits, i) == 0 {
			if n.zero == nil {
				n.zero = &tnode{}
			}
			n = n.zero
		} else {
			if n.one == nil {
				n.one = &tnode{}
			}
			n = n.one
		}
	}
	n.isp = isp
}

// matchLongest 最长前缀匹配：一路下行，记录最深有效节点携带的运营商。
func (t *binaryTrie) matchLongest(bits []byte) (ISP, bool) {
	n := t.root
	best := n.isp
	hit := n.isp != ""
	for i := 0; i < len(bits)*8; i++ {
		if bitAt(bits, i) == 0 {
			n = n.zero
		} else {
			n = n.one
		}
		if n == nil {
			break
		}
		if n.isp != "" {
			best = n.isp
			hit = true
		}
	}
	return best, hit
}

// bitAt 取 bits 第 i 位（最高位为 0）
func bitAt(bits []byte, i int) byte {
	return (bits[i>>3] >> (7 - (i & 7))) & 1
}

// snapshot 不可变快照：v4/v6 两棵子树 + 版本信息
type snapshot struct {
	v4  *binaryTrie
	v6  *binaryTrie
	ver string
}

// DB 运营商来源库
type DB struct {
	ptr atomic.Pointer[snapshot]
}

// New 返回一个空的运营商库（未命中任何段）
func New() *DB {
	d := &DB{}
	d.ptr.Store(&snapshot{v4: newTrie(), v6: newTrie()})
	return d
}

// Lookup 返回 IP 归属的运营商；未命中返回 (ISPOther, false)。
func (d *DB) Lookup(addr netip.Addr) (ISP, bool) {
	s := d.ptr.Load()
	if s == nil || !addr.IsValid() {
		return ISPOther, false
	}
	b := addr.As16()
	if addr.Is4() || addr.Is4In6() {
		if isp, ok := s.v4.matchLongest(b[12:16]); ok { // v4 使用低 4 字节前 32 位
			return isp, true
		}
		return ISPOther, false
	}
	if isp, ok := s.v6.matchLongest(b[:16]); ok {
		return isp, true
	}
	return ISPOther, false
}

// NormalizePrefix 统一 AS 归一：返回补全主机位后的掩码前缀
func NormalizePrefix(p netip.Prefix) netip.Prefix { return p.Masked() }
