package database

import (
	"strings"
	"time"
)

// 版本匹配层：借鉴 fastpoc 的做法——同一个版本号保留两种读法，
// 两种读法结论不一致时不下判决，而是交给人工/Agent（needs_manual）。
//
//   - compareUpstream：尾段数字按 semver 预发布处理（1.0 > 1.0b3）
//   - compareRevision：尾段数字按发行版修订处理（2.4.49-1 的 -1 是 Debian 修订）
//
// 现实里 Debian/Ubuntu 会把补丁回移到旧上游版本，所以"上游看起来受影响"
// 不等于"该发行版受影响"；两个比较器打架恰好说明这里必须人看。

// distroMarkers 识别发行版修订后缀（含 +deb13u4 / ~deb12u1 / -1 这类纯数字修订的判定辅助）。
var distroMarkers = []string{
	"ubuntu", "deb", ".el", "el5", "el6", "el7", "el8", "el9", "el10",
	"rhs", "suse", "centos", ".fc", "amzn", "bpo", "bsos",
}

// hasDistroSuffix 判断版本是否带发行版修订（这类版本必须核对补丁状态）。
func hasDistroSuffix(version string) bool {
	v := strings.ToLower(strings.TrimSpace(version))
	for _, mark := range distroMarkers {
		if strings.Contains(v, mark) {
			return true
		}
	}
	// 纯数字尾段（2.4.49-1 / 1:9.6p1-3）也可能是 Debian 修订，交给 Ambiguous 再判断
	_, _, ok := stripRevisionLoose(v)
	return ok && ambiguousRevision(v)
}

// stripRevisionLoose 把版本拆成 (上游部分, 修订部分)。
//
// 认两种写法：
//   - 带发行版字样：1.1.1f-1ubuntu2.16 → (1.1.1f, 1ubuntu2.16)
//   - 纯数字/点尾段：2.4.49-1 → (2.4.49, 1)
func stripRevisionLoose(v string) (base, rev string, ok bool) {
	v = strings.TrimSpace(v)
	lower := strings.ToLower(v)
	for _, mark := range distroMarkers {
		i := strings.Index(lower, mark)
		if i <= 0 {
			continue
		}
		// 优先按 '-' 切：`10.0p1-7+deb13u4` 的修订是 `7+deb13u4`，
		// 按 '+' 切会把数字修订丢掉，导致 -7 与 -8 比出相等。
		cut := lower[:i]
		j := strings.LastIndex(cut, "-")
		if j <= 0 {
			j = strings.LastIndexAny(cut, "+~")
		}
		if j > 0 {
			return strings.TrimSpace(v[:j]), strings.TrimSpace(v[j+1:]), true
		}
	}
	if i := strings.LastIndexAny(v, "-+"); i > 0 && i < len(v)-1 {
		part := v[i+1:]
		allNum := true
		for _, c := range part {
			if (c < '0' || c > '9') && c != '.' {
				allNum = false
				break
			}
		}
		if allNum {
			return strings.TrimSpace(v[:i]), strings.TrimSpace(part), true
		}
	}
	return v, "", false
}

// ambiguousRevision 判断尾段数字是否"既可能是修订号、也可能是版本号的一部分"。
func ambiguousRevision(v string) bool {
	if _, _, ok := stripRevisionLoose(v); !ok {
		return false
	}
	// 带发行版字样的修订是明确的，不算歧义
	lower := strings.ToLower(v)
	for _, mark := range distroMarkers {
		if strings.Contains(lower, mark) {
			return false
		}
	}
	return true
}

// compareUpstream 按上游语义比较：尾段数字不当修订，字母后缀按补丁级处理。
func compareUpstream(a, b string) int {
	return compareVersions(a, b)
}

// compareRevision 按发行版修订语义比较：先比上游主体，再比修订号。
func compareRevision(a, b string) int {
	ab, arev, aok := stripRevisionLoose(a)
	bb, brev, bok := stripRevisionLoose(b)
	if !aok && !bok {
		return compareVersions(a, b)
	}
	if c := compareVersions(ab, bb); c != 0 {
		return c
	}
	switch {
	case aok && !bok:
		return 1 // 带修订号的大于同主体的裸版本
	case !aok && bok:
		return -1
	}
	return compareNatural(arev, brev)
}

// compareNatural 按数字/字母段自然序比较修订号（1ubuntu2.16 < 1ubuntu2.17）。
func compareNatural(a, b string) int {
	as := splitNatural(a)
	bs := splitNatural(b)
	for i := 0; i < len(as) || i < len(bs); i++ {
		if i >= len(as) {
			return -1
		}
		if i >= len(bs) {
			return 1
		}
		if c := compareVersionSegment(as[i], bs[i]); c != 0 {
			return c
		}
	}
	return 0
}

func splitNatural(s string) []string {
	out := []string{}
	var cur strings.Builder
	lastDigit := false
	for i, r := range s {
		isDigit := r >= '0' && r <= '9'
		if i > 0 && isDigit != lastDigit {
			out = append(out, cur.String())
			cur.Reset()
		}
		cur.WriteRune(r)
		lastDigit = isDigit
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// rangeBounds 是一条区间在判定时用到的四个边界。
type rangeBounds struct {
	startIncl, startExcl, endIncl, endExcl string
}

// matchRangeDual 用两种比较器分别判断，返回 (是否落在区间, 两个结论是否一致)。
func matchRangeDual(version string, r rangeBounds, cmp func(a, b string) int) bool {
	if r.startIncl != "" && cmp(version, r.startIncl) < 0 {
		return false
	}
	if r.startExcl != "" && cmp(version, r.startExcl) <= 0 {
		return false
	}
	if r.endIncl != "" && cmp(version, r.endIncl) > 0 {
		return false
	}
	if r.endExcl != "" && cmp(version, r.endExcl) >= 0 {
		return false
	}
	return true
}

// 包名 → 产品名的别名与排除表。
//
// 这里只处理"极易误判"的几类：
//   - linux-base / linux-libc-dev 是配置与头文件，不是内核本体
//   - python3-xxx / python-xxx 是库，不是 CPython 解释器
//   - 内核镜像类包（linux-image-* / linux-headers-*）就是内核，允许映射到 linux
var denyProductByPackage = map[string][]string{
	"linux-base":         {"linux", "linux_kernel"},
	"linux-libc-dev":     {"linux", "linux_kernel"},
	"python-debian":      {"python", "python2", "python3"},
	"python3-debian":     {"python", "python2", "python3"},
	"python3-pip":        {"python", "python2", "python3"},
	"python3-setuptools": {"python", "python2", "python3"},
	"rubygems-integration": {"rubygems", "ruby", "gem"},
}

// aliasProductByPackage 给内核镜像类包补上内核产品名（截断规则本身产不出 linux_kernel）。
var aliasProductByPackage = map[string][]string{
	"linux-image":   {"linux", "linux_kernel"},
	"linux-headers": {"linux", "linux_kernel"},
	"linux-modules": {"linux", "linux_kernel"},
	"linux-kbuild":  {"linux", "linux_kernel"},
}

// packageNeedsManual 判断"包名与产品名对不上"这类需要人工核的情况。
//
// 只在版本确实落在区间里时才用它决定要不要降级为 needs_manual：
// 名字模糊 + 命中区间 = 可能是映射错，不应当成已确认。
func packageNeedsManual(pkgName, matchedProduct string) bool {
	pkgName = strings.ToLower(strings.TrimSpace(pkgName))
	product := strings.ToLower(strings.TrimSpace(matchedProduct))
	if product == "" || pkgName == product {
		return false
	}
	// 产品名是包名按分隔符截断出来的前缀（openssh-client → openssh），属正常映射
	if strings.HasPrefix(pkgName, product+"-") || strings.HasPrefix(pkgName, product+".") {
		return false
	}
	// 别名表认定的映射（linux-image-6.12 → linux）也算正常
	for prefix, products := range aliasProductByPackage {
		if strings.HasPrefix(pkgName, prefix) {
			for _, p := range products {
				if p == product {
					return false
				}
			}
		}
	}
	return true
}

// packageMatchRank 给四态一个强弱序，用于同键去重与排序：
// affected > needs_manual > unknown > not_affected。
func packageMatchRank(status string) int {
	switch status {
	case "affected":
		return 3
	case "needs_manual":
		return 2
	case "unknown":
		return 1
	default:
		return 0
	}
}

// cveEraTooOld 判断 CVE 是否属于"太久远、区间不可信"的年代。
//
// 不直接判 not_affected（那会造成漏报），而是交给人工：宁可多看一眼。
func cveEraTooOld(published string) bool {
	published = strings.TrimSpace(published)
	if published == "" {
		return false
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05.000", "2006-01-02"} {
		if t, err := time.Parse(layout, published); err == nil {
			// 未设置发布时间的行会被驱动读成 Go 零值（0001-01-01），
			// 那不是"年代久远"，而是"信息缺失"，不能据此降级。
			if t.Year() < 1990 {
				return false
			}
			return t.Year() <= 2010
		}
	}
	return false
}
