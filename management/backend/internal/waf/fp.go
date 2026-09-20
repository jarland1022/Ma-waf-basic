package waf

import (
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// FPCandidate 误报候选：同一 URI 前缀反复命中同一规则。
type FPCandidate struct {
	URI     string `json:"uri"`
	RuleIDs string `json:"rule_ids"`
	Count   int    `json:"count"`
	Kind    string `json:"kind"`
	Note    string `json:"note"`
}

func SuggestFalsePositives(events []AttackEvent, exceptions []Exception, minCount int) []FPCandidate {
	if minCount <= 0 {
		minCount = 5
	}
	covered := map[string]bool{}
	for _, e := range exceptions {
		if !e.Enabled {
			continue
		}
		key := e.Kind + "|" + strings.TrimSpace(e.URI) + "|" + compactIDs(e.RuleIDs)
		covered[key] = true
	}
	counts := map[string]int{}
	for _, ev := range events {
		uri := normalizeFPURI(ev.URI)
		if uri == "" || uri == "/" {
			continue
		}
		ids := compactIDs(strings.Join(ev.RuleIDs, ","))
		if ids == "" {
			continue
		}
		counts[uri+"\t"+ids]++
	}
	type kv struct {
		uri, ids string
		n        int
	}
	var list []kv
	for k, n := range counts {
		if n < minCount {
			continue
		}
		parts := strings.SplitN(k, "\t", 2)
		list = append(list, kv{uri: parts[0], ids: parts[1], n: n})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].n > list[j].n })
	if len(list) > 20 {
		list = list[:20]
	}
	out := make([]FPCandidate, 0, len(list))
	for _, x := range list {
		kind := "uri_rule_remove"
		ck := kind + "|" + x.uri + "|" + x.ids
		if covered[ck] {
			continue
		}
		out = append(out, FPCandidate{
			URI:     x.uri,
			RuleIDs: x.ids,
			Count:   x.n,
			Kind:    kind,
			Note:    "suggested from audit (" + strconv.Itoa(x.n) + " hits)",
		})
	}
	return out
}

func normalizeFPURI(u string) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return ""
	}
	if i := strings.IndexAny(u, " \t"); i > 0 {
		u = u[:i]
	}
	if strings.Contains(u, "://") {
		if parsed, err := url.Parse(u); err == nil && parsed.Path != "" {
			u = parsed.Path
		}
	}
	if q := strings.IndexByte(u, '?'); q >= 0 {
		u = u[:q]
	}
	if len(u) > 96 {
		u = u[:96]
	}
	return u
}

func compactIDs(s string) string {
	var ids []string
	seen := map[string]bool{}
	for _, p := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';' || r == '|'
	}) {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		ids = append(ids, p)
	}
	sort.Strings(ids)
	if len(ids) > 8 {
		ids = ids[:8]
	}
	return strings.Join(ids, ",")
}
