package consent

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heainframework/heain-consent/internal/store"
	"github.com/heainframework/heain-sdk/heain"
)

// ---- a fake platform: core (P5, discover, KMS, audit), heain-notify, and apps with subject.rights ----

type fakeApp struct {
	failFirst int // calls to fail before answering
	people    map[string][]heain.SubjectItem
	held      map[string][]heain.SubjectItem
	calls     []heain.SubjectRequest
}

type fake struct {
	mu       sync.Mutex
	n        int
	actions  map[string]heain.PolicyResult
	props    []heain.Proposal
	insts    []heain.Instance
	apps     map[string]*fakeApp // app.instance
	messages []map[string]any
	audits   []string
	key      *ecdsa.PrivateKey
}

func newFake() *fake {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &fake{actions: map[string]heain.PolicyResult{}, apps: map[string]*fakeApp{}, key: k}
}

func (f *fake) Propose(_ context.Context, p heain.Proposal) (heain.PolicyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	r := heain.PolicyResult{ActionID: fmt.Sprintf("act-%d", f.n), Type: p.Type, Result: heain.ResultWaitingApproval}
	f.actions[r.ActionID], f.props = r, append(f.props, p)
	return r, nil
}

func (f *fake) decide(id, result string) {
	f.mu.Lock()
	r := f.actions[id]
	r.Result = result
	f.actions[id] = r
	f.mu.Unlock()
}

func (f *fake) last(typ string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := f.n; i > 0; i-- {
		if r := f.actions[fmt.Sprintf("act-%d", i)]; r.Type == typ {
			return r.ActionID
		}
	}
	return ""
}

func (f *fake) PolicyStatus(_ context.Context, id string) (heain.PolicyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.actions[id]
	if !ok {
		return r, errors.New("no such action")
	}
	return r, nil
}

func (f *fake) Discover(_ context.Context, c string, _ int) ([]heain.Instance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c != heain.SubjectRightsCapability {
		return nil, nil
	}
	return append([]heain.Instance(nil), f.insts...), nil
}

func (f *fake) addApp(app, inst string, a *fakeApp) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.insts = append(f.insts, heain.Instance{AppID: app, InstanceID: inst, EndpointBase: "https://x", Execution: "direct"})
	f.apps[app+"."+inst] = a
}

func (f *fake) Call(_ context.Context, cs heain.CallSpec) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if cs.App == "heain-notify" {
		m := map[string]any{}
		raw, _ := json.Marshal(cs.Body)
		_ = json.Unmarshal(raw, &m)
		f.messages = append(f.messages, m)
		return 202, nil
	}
	a := f.apps[cs.App+"."+cs.Instance]
	if a == nil || cs.Instance == "" {
		return 0, errors.New("no instance")
	}
	q := cs.Body.(heain.SubjectRequest)
	a.calls = append(a.calls, q)
	if a.failFirst > 0 {
		a.failFirst--
		return 503, &heain.CallError{Status: 503}
	}
	var mine []heain.SubjectItem
	var held []heain.SubjectItem
	whos := map[string]bool{}
	for who := range a.people {
		whos[who] = true
	}
	for who := range a.held {
		whos[who] = true
	}
	for who := range whos {
		items := a.people[who]
		if q.Has(heain.IdentEmail, who) {
			mine = append(mine, items...)
			if q.Override == "" {
				held = append(held, a.held[who]...)
			} else {
				for _, h := range a.held[who] {
					mine = append(mine, heain.SubjectItem{Kind: h.Kind, ID: h.ID})
				}
			}
			if strings.HasSuffix(cs.Path, "/erase") && !q.DryRun {
				delete(a.people, who)
				if q.Override != "" {
					delete(a.held, who)
				}
			}
		}
	}
	raw, _ := json.Marshal(map[string]any{"items": mine, "erased": mine, "held": held})
	return 200, json.Unmarshal(raw, cs.Out)
}

func (f *fake) SignDigest(d []byte) ([]byte, error) { return f.key.Sign(rand.Reader, d, crypto.SHA256) }
func (f *fake) CertDER() []byte                     { return []byte("cert") }
func (f *fake) Audit(_ context.Context, c, o string, _ map[string]any) error {
	f.mu.Lock()
	f.audits = append(f.audits, c+":"+o)
	f.mu.Unlock()
	return nil
}

func (f *fake) told(sub string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, m := range f.messages {
		raw, _ := json.Marshal(m)
		if strings.Contains(string(raw), sub) {
			n++
		}
	}
	return n
}

type keys struct {
	mu sync.Mutex
	k  map[string]*heain.Sealer
}

func (k *keys) sealer(_ context.Context, name string) (*heain.Sealer, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if s, ok := k.k[name]; ok {
		return s, nil
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	s, _ := heain.NewSealer(b)
	k.k[name] = s
	return s, nil
}

func (k *keys) destroy(_ context.Context, name string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.k, name)
	return nil
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func setup(t *testing.T) (*Engine, *fake, *clock, string) {
	t.Helper()
	inside := make([]byte, 32)
	_, _ = rand.Read(inside)
	k := &keys{k: map[string]*heain.Sealer{}}
	path := filepath.Join(t.TempDir(), "consent.db")
	st, err := store.Open(path, inside, store.Keys{Sealer: k.sealer, Destroy: k.destroy})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	f := newFake()
	c := &clock{time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)}
	e := New(&Engine{Store: st, Plat: f, Now: c.now, Logf: t.Logf, Cfg: Config{PollEvery: time.Nanosecond, MaxAttempts: 3}})
	return e, f, c, path
}

func ticks(e *Engine, c *clock, n int) {
	for i := 0; i < n; i++ {
		c.t = c.t.Add(time.Second)
		e.Tick(context.Background())
	}
}

func purpose(t *testing.T, e *Engine, f *fake, c *clock, id, basis string, reconsent bool) int {
	t.Helper()
	v, err := e.SubmitPurpose(context.Background(), id, PurposeInput{Title: "Marketing", Notice: "We send offers by e-mail.", LawfulBasis: basis, Reconsent: reconsent}, "admin")
	if err != nil || v.State != "proposed" {
		t.Fatalf("submit: %v %+v", err, v)
	}
	f.decide(v.ActionID, heain.ResultApproved)
	ticks(e, c, 1)
	p, _ := e.Store.Purpose(id)
	if p.Active != v.N {
		t.Fatalf("not active: %+v", p)
	}
	return v.N
}

func TestPurposesAndConsent(t *testing.T) {
	e, f, c, _ := setup(t)
	ctx := context.Background()
	if _, err := e.SubmitPurpose(ctx, "m", PurposeInput{Title: "x", Notice: "y", LawfulBasis: "because"}, "a"); err == nil {
		t.Fatal("a bad lawful basis must be refused")
	}
	v, _ := e.SubmitPurpose(ctx, "marketing", PurposeInput{Title: "Marketing", Notice: "We send offers.", LawfulBasis: "consent"}, "admin")
	sub, created, err := e.RegisterSubject(ctx, []heain.SubjectIdentifier{{Kind: "email", Value: "Somchai@Example.test"}, {Kind: "gateway_user", Value: "somchai"}})
	if err != nil || !created {
		t.Fatal(err)
	}
	if _, err := e.Record(ctx, sub.ID, "marketing", 1, true, "somchai", "self", ""); err == nil {
		t.Fatal("consent to a purpose not yet active (P5) must be refused")
	}
	if _, err := e.CheckConsent(ctx, "marketing", sub.ID, nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("check before activation: %v", err)
	}
	f.decide(v.ActionID, heain.ResultApproved)
	ticks(e, c, 1)
	if ch, _ := e.CheckConsent(ctx, "marketing", sub.ID, nil); ch.Allowed || ch.Reason != "no consent recorded" {
		t.Fatalf("no consent yet: %+v", ch)
	}
	if _, err := e.Record(ctx, sub.ID, "marketing", 2, true, "somchai", "self", ""); err == nil {
		t.Fatal("consent to a version that is not the active one must be refused")
	}
	if _, err := e.Record(ctx, sub.ID, "marketing", 1, true, "somchai", "self", ""); err != nil {
		t.Fatal(err)
	}
	// found by any identifier, normalized
	if ch, _ := e.CheckConsent(ctx, "marketing", "", []heain.SubjectIdentifier{{Kind: "email", Value: " SOMCHAI@example.test"}}); !ch.Allowed || ch.ConsentedVersion != 1 {
		t.Fatalf("given: %+v", ch)
	}
	if ch, _ := e.CheckConsent(ctx, "marketing", "", []heain.SubjectIdentifier{{Kind: "email", Value: "nobody@example.test"}}); ch.Allowed {
		t.Fatal("an unknown person has not consented")
	}
	_, _ = e.Record(ctx, sub.ID, "marketing", 0, false, "somchai", "self", "")
	if ch, _ := e.CheckConsent(ctx, "marketing", sub.ID, nil); ch.Allowed || ch.Reason != "consent withdrawn" {
		t.Fatalf("withdrawn: %+v", ch)
	}
	_, _ = e.Record(ctx, sub.ID, "marketing", 1, true, "somchai", "self", "")
	// a new version that needs consent again
	v2, _ := e.SubmitPurpose(ctx, "marketing", PurposeInput{Title: "Marketing", Notice: "We send offers by e-mail and SMS.", LawfulBasis: "consent", Reconsent: true}, "admin")
	if ch, _ := e.CheckConsent(ctx, "marketing", sub.ID, nil); !ch.Allowed || ch.Version != 1 {
		t.Fatalf("v2 only proposed: v1 still counts: %+v", ch)
	}
	f.decide(v2.ActionID, heain.ResultApproved)
	ticks(e, c, 1)
	if ch, _ := e.CheckConsent(ctx, "marketing", sub.ID, nil); ch.Allowed || ch.Version != 2 || !strings.Contains(ch.Reason, "no longer counts") {
		t.Fatalf("v2 needs consent again: %+v", ch)
	}
	_, _ = e.Record(ctx, sub.ID, "marketing", 2, true, "somchai", "self", "")
	if ch, _ := e.CheckConsent(ctx, "marketing", sub.ID, nil); !ch.Allowed {
		t.Fatalf("v2 given: %+v", ch)
	}
	// another lawful basis needs no consent
	purpose(t, e, f, c, "billing", "contract", false)
	if ch, _ := e.CheckConsent(ctx, "billing", "", []heain.SubjectIdentifier{{Kind: "email", Value: "nobody@example.test"}}); !ch.Allowed || ch.LawfulBasis != "contract" {
		t.Fatalf("contract: %+v", ch)
	}
	// identifiers of two different people
	other, _, _ := e.RegisterSubject(ctx, []heain.SubjectIdentifier{{Kind: "email", Value: "mali@example.test"}})
	if _, _, err := e.RegisterSubject(ctx, []heain.SubjectIdentifier{{Kind: "email", Value: "mali@example.test"}, {Kind: "gateway_user", Value: "somchai"}}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("conflict: %v", err)
	}
	if again, created, _ := e.RegisterSubject(ctx, []heain.SubjectIdentifier{{Kind: "email", Value: "MALI@example.test"}, {Kind: "phone", Value: "+66 81 111 2222"}}); created || again.ID != other.ID || len(again.Identifiers) != 2 {
		t.Fatalf("merge: %+v", again)
	}
	if _, err := CleanIdentifiers([]heain.SubjectIdentifier{{Kind: "email", Value: "not-an-address"}}); err == nil {
		t.Fatal("a bad e-mail")
	}
}

func TestAccessRequest(t *testing.T) {
	e, f, c, path := setup(t)
	ctx := context.Background()
	purpose(t, e, f, c, "marketing", "consent", false)
	f.addApp("crm", "c1", &fakeApp{failFirst: 1, people: map[string][]heain.SubjectItem{"somchai@example.test": {{Kind: "customer", ID: "c-1", Data: map[string]any{"name": "Somchai"}}}}})
	f.addApp("crm", "c2", &fakeApp{people: map[string][]heain.SubjectItem{"somchai@example.test": {{Kind: "customer", ID: "c-9", Data: map[string]any{"city": "Chiang Mai"}}}}})
	f.addApp("shop", "s1", &fakeApp{people: map[string][]heain.SubjectItem{}})
	sub, _, _ := e.RegisterSubject(ctx, []heain.SubjectIdentifier{{Kind: "gateway_user", Value: "somchai"}})
	_, _ = e.Record(ctx, sub.ID, "marketing", 1, true, "somchai", "self", "")
	r, err := e.File(ctx, sub.ID, "access", "please", nil, "somchai", "self")
	if err != nil || r.Status != StReceived || !r.Due.Equal(c.t.UTC().Add(30*24*time.Hour)) {
		t.Fatalf("file: %v %+v", err, r)
	}
	if f.told("group:dpo") != 1 {
		t.Fatal("the DPO group was not told")
	}
	ticks(e, c, 3)
	if r, _ = e.Store.Request(ctx, r.ID); r.Status != StReceived {
		t.Fatalf("nothing happens before the DPO verifies: %s", r.Status)
	}
	if _, err := e.Verify(ctx, r.ID, true, "ID card seen", "dpo1", []heain.SubjectIdentifier{{Kind: "email", Value: "somchai@example.test"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Verify(ctx, r.ID, true, "again", "dpo1", nil); !errors.Is(err, ErrState) {
		t.Fatal("a request is verified once")
	}
	ticks(e, c, 5)
	r, _ = e.Store.Request(ctx, r.ID)
	if r.Status != StCompleted || r.Bundle == "" || len(r.Results) != 3 || r.Collected != nil {
		t.Fatalf("access: %+v", r)
	}
	if r.Results[0].App != "crm" || r.Results[0].Attempts != 1 || r.Results[0].Items != 1 || r.Results[2].Items != 0 {
		t.Fatalf("results: %+v", r.Results)
	}
	b, err := e.Store.Bundle(ctx, r.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b.Body)
	if !ecdsa.VerifyASN1(&f.key.PublicKey, h[:], b.Signature) {
		t.Fatal("bundle signature")
	}
	var body ExportBody
	_ = json.Unmarshal(b.Body, &body)
	if body.Format != "heain-consent-export/1" || len(body.Apps) != 3 || len(body.Identifiers) != 2 || len(body.Consents) != 1 || !strings.Contains(string(b.Body), "Chiang Mai") {
		t.Fatalf("bundle: %s", b.Body)
	}
	if f.told("gateway_user:somchai") != 1 {
		t.Fatal("somchai was not told")
	}
	// at rest: nothing readable
	raw, _ := os.ReadFile(path)
	for _, s := range []string{"Chiang Mai", "somchai@example.test", "ID card seen", "please"} {
		if strings.Contains(string(raw), s) {
			t.Fatalf("%q in consent.db", s)
		}
	}
	// the export expires: its key is destroyed
	c.t = c.t.Add(31 * 24 * time.Hour)
	e.Tick(ctx)
	if _, err := e.Store.Bundle(ctx, r.Bundle); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired bundle: %v", err)
	}
}

func erasureSetup(t *testing.T) (*Engine, *fake, *clock, store.Subject, *fakeApp, string) {
	e, f, c, _ := setup(t)
	ctx := context.Background()
	purpose(t, e, f, c, "marketing", "consent", false)
	crm := &fakeApp{people: map[string][]heain.SubjectItem{"somchai@example.test": {{Kind: "customer", ID: "c-1"}}},
		held: map[string][]heain.SubjectItem{"somchai@example.test": {{Kind: "invoice", ID: "inv-1", Reason: "retention_min"}}}}
	f.addApp("crm", "c1", crm)
	f.addApp("heain-consent", "k1", &fakeApp{}) // itself: never called
	sub, _, _ := e.RegisterSubject(ctx, []heain.SubjectIdentifier{{Kind: "gateway_user", Value: "somchai"}, {Kind: "email", Value: "somchai@example.test"}})
	_, _ = e.Record(ctx, sub.ID, "marketing", 1, true, "somchai", "self", "")
	r, _ := e.File(ctx, sub.ID, "erasure", "", nil, "somchai", "self")
	_, _ = e.Verify(ctx, r.ID, true, "ok", "dpo1", nil)
	ticks(e, c, 3)
	return e, f, c, sub, crm, r.ID
}

func TestErasureWithOverride(t *testing.T) {
	e, f, c, sub, crm, id := erasureSetup(t)
	ctx := context.Background()
	r, _ := e.Store.Request(ctx, id)
	if r.Status != StAwaitingApproval || len(r.Plan) != 1 || len(r.Plan[0].Erased) != 1 || len(r.Plan[0].Held) != 1 || !crm.calls[0].DryRun {
		t.Fatalf("plan: %+v", r)
	}
	if len(crm.people) != 1 {
		t.Fatal("a dry run erased something")
	}
	if len(f.apps["heain-consent.k1"].calls) != 0 {
		t.Fatal("heain-consent called itself")
	}
	f.decide(r.ActionID, heain.ResultApproved)
	ticks(e, c, 3)
	r, _ = e.Store.Request(ctx, id)
	if r.Status != StAwaitingOverride || r.Override == "" || f.last("consent.erasure.override") != r.Override {
		t.Fatalf("override: %+v", r)
	}
	f.mu.Lock()
	cat := f.props[len(f.props)-1].Category
	f.mu.Unlock()
	if cat != heain.CategoryRetentionOverride || len(crm.people) != 0 || len(crm.held) != 1 {
		t.Fatalf("after the first pass: %s %v %v", cat, crm.people, crm.held)
	}
	f.decide(r.Override, heain.ResultApproved)
	ticks(e, c, 3)
	r, _ = e.Store.Request(ctx, id)
	if r.Status != StCompleted || len(crm.held) != 0 || crm.calls[len(crm.calls)-1].Override != r.Override || len(r.Results[0].Erased) != 2 {
		t.Fatalf("erased: %+v %v", r, crm.held)
	}
	if _, err := e.Store.Subject(ctx, sub.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("the subject's record was not shredded")
	}
	if id, _ := e.Store.Find([]heain.SubjectIdentifier{{Kind: "email", Value: "somchai@example.test"}}); id != "" {
		t.Fatal("the identifiers still lead somewhere")
	}
	if f.told("gateway_user:somchai") != 1 {
		t.Fatal("somchai was not told")
	}
	// the request (no personal data) stays as the proof
	if r.Results[0].Erased[0].Data != nil {
		t.Fatal("data in the request record")
	}
}

func TestErasureOverrideDenied(t *testing.T) {
	e, f, c, sub, crm, id := erasureSetup(t)
	ctx := context.Background()
	r, _ := e.Store.Request(ctx, id)
	f.decide(r.ActionID, heain.ResultApproved)
	ticks(e, c, 3)
	r, _ = e.Store.Request(ctx, id)
	f.decide(r.Override, heain.ResultDenied)
	ticks(e, c, 3)
	r, _ = e.Store.Request(ctx, id)
	if r.Status != StCompletedHolds || !strings.Contains(r.Outcome, "1 held (retention_min)") || len(crm.held) != 1 {
		t.Fatalf("holds: %+v", r)
	}
	s, err := e.Store.Subject(ctx, sub.ID)
	if err != nil {
		t.Fatal("the subject stays while something is held")
	}
	if ch, _ := e.CheckConsent(ctx, "marketing", s.ID, nil); ch.Allowed {
		t.Fatal("consents must be withdrawn")
	}
}

func TestErasureRefused(t *testing.T) {
	e, f, c, sub, crm, id := erasureSetup(t)
	ctx := context.Background()
	r, _ := e.Store.Request(ctx, id)
	f.decide(r.ActionID, heain.ResultDenied)
	ticks(e, c, 3)
	r, _ = e.Store.Request(ctx, id)
	if r.Status != StRefused || len(crm.people) != 1 || len(crm.calls) != 1 {
		t.Fatalf("refused: %+v", r)
	}
	if _, err := e.Store.Subject(ctx, sub.ID); err != nil {
		t.Fatal(err)
	}
}

func TestDPOAndDeadlines(t *testing.T) {
	e, f, c, _ := setup(t)
	ctx := context.Background()
	purpose(t, e, f, c, "marketing", "consent", false)
	sub, _, _ := e.RegisterSubject(ctx, []heain.SubjectIdentifier{{Kind: "gateway_user", Value: "mali"}})
	_, _ = e.Record(ctx, sub.ID, "marketing", 1, true, "mali", "self", "")
	if _, err := e.File(ctx, sub.ID, "delete-everything", "", nil, "mali", "self"); err == nil {
		t.Fatal("an unknown type")
	}
	r1, _ := e.File(ctx, sub.ID, "access", "", nil, "mali", "self")
	r2, _ := e.File(ctx, sub.ID, "objection", "no more marketing", []string{"marketing"}, "mali", "self")
	r3, _ := e.File(ctx, sub.ID, "restriction", "", nil, "mali", "self")
	if r, _ := e.Verify(ctx, r1.ID, false, "could not verify", "dpo1", nil); r.Status != StRejected {
		t.Fatalf("reject: %+v", r)
	}
	if _, err := e.Complete(ctx, r2.ID, "done", "dpo1", []string{"marketing"}, nil); !errors.Is(err, ErrState) {
		t.Fatal("complete before verify")
	}
	_, _ = e.Verify(ctx, r2.ID, true, "ok", "dpo1", nil)
	if r, _ := e.Complete(ctx, r2.ID, "marketing stopped", "dpo1", []string{"marketing"}, nil); r.Status != StCompleted {
		t.Fatalf("objection: %+v", r)
	}
	if ch, _ := e.CheckConsent(ctx, "marketing", sub.ID, nil); ch.Allowed {
		t.Fatal("the objection withdrew marketing")
	}
	_, _ = e.Record(ctx, sub.ID, "marketing", 1, true, "mali", "self", "")
	_, _ = e.Verify(ctx, r3.ID, true, "ok", "dpo1", nil)
	yes := true
	_, _ = e.Complete(ctx, r3.ID, "restricted", "dpo1", nil, &yes)
	if ch, _ := e.CheckConsent(ctx, "marketing", sub.ID, nil); ch.Allowed || ch.Reason != "restricted" {
		t.Fatalf("restricted: %+v", ch)
	}
	// deadlines: one more request left open
	r4, _ := e.File(ctx, sub.ID, "rectification", "my name is wrong", nil, "mali", "self")
	c.t = c.t.Add(24 * 24 * time.Hour)
	e.Tick(ctx)
	e.Tick(ctx)
	c.t = c.t.Add(7 * 24 * time.Hour)
	e.Tick(ctx)
	e.Tick(ctx)
	r4, _ = e.Store.Request(ctx, r4.ID)
	if strings.Join(r4.Reminded, ",") != "due_soon,overdue" {
		t.Fatalf("reminders: %v", r4.Reminded)
	}
	n := 0
	f.mu.Lock()
	for _, m := range f.messages {
		if m["ref"] == r4.ID {
			n++
		}
	}
	f.mu.Unlock()
	if n != 3 { // received, due soon, overdue
		t.Fatalf("messages about r4: %d", n)
	}
}
