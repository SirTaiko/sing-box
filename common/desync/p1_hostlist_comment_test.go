package desync

// Pinned hostlist comment grammar regressions.
//
// Pinned nfq/hostlist.c addpool() treats a record whose first byte is '#', ';'
// or '/' as a comment line, so a comment-only file contributes zero hosts. The
// runtime list reader used to ignore only '#': an exclusion file holding just
// "; disable" or "/ disable" became a nonempty exclusion collection, and the
// repaired unknown-hostname matcher then refused a rule that pinned effective
// empties leave reachable. These tests keep the correction narrow: the
// positive-domain-empty semantic, the positive-IP empty aggregate, include and
// exclusion priority, wildcard suffixes, bundle datasets and a transactional
// reload-last-good path all stay as accepted.

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// p1CommentRule compiles one rule with the given extra JSON fields. The rule
// carries any_protocol so a single unknown address exercises reachability
// without inventing a hostname fact.
func p1CommentRule(t *testing.T, dir, extra string) *Rule {
	t.Helper()
	fields := ""
	if extra != "" {
		fields = "," + extra
	}
	config, err := Compile(enabledOption(`{"enabled":true,"rules":[{`+
		`"network":["tcp"],"port":[8443],"any_protocol":true`+fields+`,"methods":["fake"],`+
		`"fake":{"repeats":1,"payloads":[{"protocol":"unknown","hex":"aa"}]}}]}`), dir)
	if err != nil {
		t.Fatalf("pinned comment-only hostlist must compile: %v", err)
	}
	return config.Rules[0]
}

func p1WriteFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func p1GzipBytes(t *testing.T, content []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

var p1UnknownFacts = MatchFacts{Family: FamilyIPv4, Transport: TransportTCP,
	Destination: netip.MustParseAddr("1.1.1.1"), Port: 8443, Protocol: ProtocolUnknown}

// TestP1HostlistCommentOnlyExclusion reproduces the independent QA defect: a
// pinned-valid comment-only exclusion file must be an empty collection and the
// unknown-hostname rule must stay reachable. Plain text, CRLF and gzip input
// are all parsed by the same bounded reader.
func TestP1HostlistCommentOnlyExclusion(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		content string
		gzip    bool
	}{
		{name: "hash", content: "# comment\n"},
		{name: "semicolon", content: "; comment\n"},
		{name: "slash", content: "/ comment\n"},
		{name: "crlf", content: "; comment\r\n/ comment\r\n"},
		{name: "mixed", content: "# hash\n; semicolon\n/ slash\n\n"},
		{name: "semicolon-gzip", content: "; comment\n", gzip: true},
		{name: "slash-gzip", content: "/ comment\n", gzip: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			dir := t.TempDir()
			content := []byte(testCase.content)
			if testCase.gzip {
				content = p1GzipBytes(t, content)
			}
			p1WriteFile(t, filepath.Join(dir, "exclude.txt"), content)
			rule := p1CommentRule(t, dir, `"domain_exclude_file":["exclude.txt"]`)
			if !rule.DomainsExclude.empty() {
				t.Fatalf("comment-only exclusion parsed as %v; pinned hostlist.c contributes no entries", rule.DomainsExclude)
			}
			if !rule.Matches(p1UnknownFacts) {
				t.Fatal("pinned comment-only exclusion must leave the unknown-hostname rule reachable")
			}
		})
	}
}

// TestP1HostlistCommentMixesWithRealEntries keeps the priority semantics: a
// comment is not an entry, but a real entry beside it keeps its full effect.
func TestP1HostlistCommentMixesWithRealEntries(t *testing.T) {
	dir := t.TempDir()
	p1WriteFile(t, filepath.Join(dir, "exclude.txt"), []byte("; comment\nblocked.example\n"))
	rule := p1CommentRule(t, dir, `"domain_exclude_file":["exclude.txt"]`)
	if rule.DomainsExclude.empty() {
		t.Fatal("a real exclusion entry must keep the collection nonempty")
	}
	// An unknown hostname cannot be checked against a nonempty exclusion set,
	// exactly like the repaired pinned dp_match gate.
	if rule.Matches(p1UnknownFacts) {
		t.Fatal("a nonempty exclusion collection must keep an unknown host unreachable")
	}
	excluded := p1UnknownFacts
	excluded.Host, excluded.HostKnown = "blocked.example", true
	if rule.Matches(excluded) {
		t.Fatal("a listed exclusion must win")
	}
	allowed := p1UnknownFacts
	allowed.Host, allowed.HostKnown = "allowed.example", true
	if !rule.Matches(allowed) {
		t.Fatal("an unlisted hostname must stay reachable")
	}

	// A wildcard exclusion keeps its subdomain-only meaning next to comments.
	p1WriteFile(t, filepath.Join(dir, "exclude.txt"), []byte("/ comment\n.blocked.example\n"))
	rule = p1CommentRule(t, dir, `"domain_exclude_file":["exclude.txt"]`)
	subdomain := p1UnknownFacts
	subdomain.Host, subdomain.HostKnown = "sub.blocked.example", true
	if rule.Matches(subdomain) {
		t.Fatal("a .suffix exclusion must keep matching subdomains")
	}
	apex := p1UnknownFacts
	apex.Host, apex.HostKnown = "blocked.example", true
	if !rule.Matches(apex) {
		t.Fatal("a .suffix exclusion must not match the apex")
	}
}

// TestP1HostlistCommentKeepsIncludeAndEmptySemantics pins the preserved rules:
// comment lines inside an include file do not create a positive entry, a
// positive domain source that resolves to nothing still matches nothing
// (accepted candidate semantic), and a comment-only positive IP aggregate still
// imposes no positive-IP restriction (pinned all-empty include compat).
func TestP1HostlistCommentKeepsIncludeAndEmptySemantics(t *testing.T) {
	dir := t.TempDir()
	p1WriteFile(t, filepath.Join(dir, "include.txt"), []byte("; comment\nallowed.example\n"))
	p1WriteFile(t, filepath.Join(dir, "exclude.txt"), []byte("/ comment\nblocked.example\n"))
	rule := p1CommentRule(t, dir, `"domain_file":["include.txt"],"domain_exclude_file":["exclude.txt"]`)
	allowed := p1UnknownFacts
	allowed.Host, allowed.HostKnown = "allowed.example", true
	if !rule.Matches(allowed) {
		t.Fatal("an included hostname beside a comment must match")
	}
	blocked := p1UnknownFacts
	blocked.Host, blocked.HostKnown = "blocked.example", true
	if rule.Matches(blocked) {
		t.Fatal("exclusions must win over includes")
	}
	outside := p1UnknownFacts
	outside.Host, outside.HostKnown = "outside.example", true
	if rule.Matches(outside) {
		t.Fatal("a nonempty include collection must keep restricting")
	}

	// A positive domain source made only of comments is still a configured
	// restriction and matches nothing.
	p1WriteFile(t, filepath.Join(dir, "comments-only.txt"), []byte("; comment\n/ comment\n# comment\n"))
	empty := p1CommentRule(t, dir, `"domain_file":["comments-only.txt"]`)
	if !empty.domainRestrict || !empty.Domains.empty() {
		t.Fatal("a comment-only positive domain file must stay an active empty restriction")
	}
	if empty.Matches(p1UnknownFacts) {
		t.Fatal("an empty positive domain restriction must match nothing")
	}

	// The positive-IP aggregate keeps the pinned empty-include compatibility.
	p1WriteFile(t, filepath.Join(dir, "ips.txt"), []byte("; comment\n/ comment\n"))
	ipRule := p1CommentRule(t, dir, `"ip_cidr_file":["ips.txt"]`)
	if ipRule.IPs.restricts() || len(ipRule.IPs.prefixes) != 0 {
		t.Fatal("a comment-only positive IP aggregate must impose no restriction")
	}
	if !ipRule.Matches(p1UnknownFacts) {
		t.Fatal("the empty positive-IP compatibility must keep the rule reachable")
	}
}

// TestP1HostlistCommentBundleDataset keeps the bundle path honest. The
// accepted local publisher normalises snapshot entries before publication (a
// snapshot with no valid record is refused by the provider, so an
// effectively-empty exclusion cannot be constructed through that path); the
// runtime therefore receives only real entries, comments beside them change
// nothing, and the exclusion keeps its full restriction.
func TestP1HostlistCommentBundleDataset(t *testing.T) {
	root := t.TempDir()
	buildLocalBundle(t, root, map[string]string{
		"hosts": "; comment\nblocked.example\n",
	})
	selector := `"list_bundle":{"manifest":` + string(mustJSON(t, filepath.Join(root, "current.json"))) +
		`,"domain_exclude":["hosts"]}`
	rule := p1CommentRule(t, "", selector)
	if rule.DomainsExclude.empty() {
		t.Fatal("a published exclusion dataset with one real entry must stay nonempty")
	}
	if rule.Matches(p1UnknownFacts) {
		t.Fatal("a nonempty bundle exclusion must keep the unknown hostname unreachable")
	}
	excluded := p1UnknownFacts
	excluded.Host, excluded.HostKnown = "blocked.example", true
	if rule.Matches(excluded) {
		t.Fatal("a bundle exclusion entry must win")
	}
	allowed := p1UnknownFacts
	allowed.Host, allowed.HostKnown = "allowed.example", true
	if !rule.Matches(allowed) {
		t.Fatal("an unlisted hostname must stay reachable beside a bundle exclusion")
	}
}

// mustJSON renders one path/ID as a JSON string literal.
func mustJSON(t *testing.T, value string) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// TestP1HostlistCommentReloadLastGood reloads the same exclusion file
// transactionally: a comment-only snapshot empties the collection, a real entry
// restores the restriction, a corrupt snapshot is refused and the last-good
// collection stays published.
func TestP1HostlistCommentReloadLastGood(t *testing.T) {
	dir := t.TempDir()
	excludePath := filepath.Join(dir, "exclude.txt")
	p1WriteFile(t, excludePath, []byte("; comment\n"))
	config, err := Compile(enabledOption(`{"enabled":true,"rules":[{`+
		`"network":["tcp"],"port":[8443],"any_protocol":true,"domain_exclude_file":["exclude.txt"],`+
		`"methods":["fake"],"fake":{"repeats":1,"payloads":[{"protocol":"unknown","hex":"aa"}]}}]}`), dir)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	if engine.ListRevision() != 1 {
		t.Fatalf("initial revision %d, want 1", engine.ListRevision())
	}
	if !engine.Config().Rules[0].Matches(p1UnknownFacts) {
		t.Fatal("comment-only exclusion must be effective-empty at compile")
	}

	p1WriteFile(t, excludePath, []byte("; comment\nblocked.example\n"))
	if changed, reloadErr := engine.ReloadListsContext(context.Background()); reloadErr != nil || !changed {
		t.Fatalf("changed reload: changed=%v err=%v", changed, reloadErr)
	}
	if engine.ListRevision() != 2 {
		t.Fatalf("revision after changed reload %d, want 2", engine.ListRevision())
	}
	if engine.Config().Rules[0].Matches(p1UnknownFacts) {
		t.Fatal("a reloaded real exclusion must keep the unknown host unreachable")
	}

	// A corrupt snapshot must not publish: the last-good exclusion stays active
	// and the revision does not move.
	p1WriteFile(t, excludePath, []byte{0x1f, 0x8b, 0x08, 0x00, 0x00})
	if changed, reloadErr := engine.ReloadListsContext(context.Background()); reloadErr == nil || changed {
		t.Fatalf("corrupt reload: changed=%v err=%v, want a refused reload", changed, reloadErr)
	}
	if engine.ListRevision() != 2 {
		t.Fatalf("failed reload changed the revision to %d", engine.ListRevision())
	}
	if engine.Config().Rules[0].DomainsExclude.empty() || engine.Config().Rules[0].Matches(p1UnknownFacts) {
		t.Fatal("a failed reload must keep the last-good exclusion collection")
	}

	p1WriteFile(t, excludePath, []byte("/ comment\n"))
	if changed, reloadErr := engine.ReloadListsContext(context.Background()); reloadErr != nil || !changed {
		t.Fatalf("comment-only reload: changed=%v err=%v", changed, reloadErr)
	}
	if engine.ListRevision() != 3 {
		t.Fatalf("revision after comment-only reload %d, want 3", engine.ListRevision())
	}
	if !engine.Config().Rules[0].DomainsExclude.empty() || !engine.Config().Rules[0].Matches(p1UnknownFacts) {
		t.Fatal("a reloaded comment-only exclusion must be effective-empty again")
	}
}
