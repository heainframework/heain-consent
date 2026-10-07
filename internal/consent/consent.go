// Package consent is heain-consent's engine (author decisions 2026-10-07):
// purposes activated through P5, people's consent and its check, and
// data-subject requests verified by a DPO and carried out in every app that
// declares subject.rights; erasure goes through P5, and what retention or a
// legal hold keeps goes through RETENTION_OVERRIDE.
package consent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/heainframework/heain-consent/internal/store"
	"github.com/heainframework/heain-sdk/heain"
)

// Roles (through heain-gateway).
const (
	AdminRole = "consent-admin" // purposes
	DPORole   = "dpo"           // data-subject requests and subjects
)

// Request types.
var RequestTypes = map[string]bool{"access": true, "portability": true, "erasure": true, "rectification": true, "restriction": true, "objection": true}

// Lawful bases (PDPA section 24 / GDPR article 6).
var LawfulBases = map[string]bool{"consent": true, "contract": true, "legal_obligation": true, "vital_interest": true, "public_task": true, "legitimate_interest": true}

// Request statuses.
const (
	StReceived         = "received"          // waiting for the DPO
	StVerified         = "verified"          // the engine takes it from here
	StInProgress       = "in_progress"       // a DPO carries it out (rectification, restriction, objection)
	StCollecting       = "collecting"        // access / portability: asking every app
	StPlanning         = "planning"          // erasure: a dry run in every app
	StAwaitingApproval = "awaiting_approval" // erasure: P5
	StErasing          = "erasing"
	StAwaitingOverride = "awaiting_override" // RETENTION_OVERRIDE for what is held
	StErasingOverride  = "erasing_override"
	StCompleted        = "completed"
	StCompletedHolds   = "completed_with_holds"
	StRejected         = "rejected" // the DPO could not verify the person
	StRefused          = "refused"  // the Approver denied the erasure
)

// Closed reports whether a request is finished.
func Closed(st string) bool {
	return st == StCompleted || st == StCompletedHolds || st == StRejected || st == StRefused
}

// Platform is what the engine needs from heain-core (through heain-sdk).
type Platform interface {
	Propose(ctx context.Context, p heain.Proposal) (heain.PolicyResult, error)
	PolicyStatus(ctx context.Context, actionID string) (heain.PolicyResult, error)
	Discover(ctx context.Context, capability string, version int) ([]heain.Instance, error)
	Call(ctx context.Context, cs heain.CallSpec) (int, error)
	SignDigest(digest []byte) ([]byte, error)
	CertDER() []byte
	Audit(ctx context.Context, capability, outcome string, d map[string]any) error
}

// Config tunes the engine.
type Config struct {
	Self            string   // this app's id (default heain-consent)
	AdminCallers    []string // apps that may act as consent-admin and DPO
	RecorderCallers []string // apps that may register people and record consent and requests for them
	NotifyApp       string   // default heain-notify
	DPOGroup        string   // heain-notify group told about requests (default dpo)
	Due             time.Duration
	RemindBefore    time.Duration
	BundleTTL       time.Duration
	PollEvery       time.Duration
	MaxAttempts     int
}

// Engine is heain-consent.
type Engine struct {
	Cfg   Config
	Store *store.Store
	Plat  Platform
	Logf  func(string, ...any)
	Now   func() time.Time

	mu   sync.Mutex // subjects, requests, purposes
	kick chan struct{}
	last time.Time // the last poll of P5 and apps
}

// New prepares an engine.
func New(e *Engine) *Engine {
	if e.Now == nil {
		e.Now = time.Now
	}
	if e.Logf == nil {
		e.Logf = func(string, ...any) {}
	}
	c := &e.Cfg
	if c.Self == "" {
		c.Self = "heain-consent"
	}
	if c.NotifyApp == "" {
		c.NotifyApp = "heain-notify"
	}
	if c.DPOGroup == "" {
		c.DPOGroup = "dpo"
	}
	if c.Due <= 0 {
		c.Due = 30 * 24 * time.Hour
	}
	if c.RemindBefore <= 0 {
		c.RemindBefore = 7 * 24 * time.Hour
	}
	if c.BundleTTL <= 0 {
		c.BundleTTL = 30 * 24 * time.Hour
	}
	if c.PollEvery <= 0 {
		c.PollEvery = 3 * time.Second
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 5
	}
	e.kick = make(chan struct{}, 1)
	return e
}

func (e *Engine) wake() {
	select {
	case e.kick <- struct{}{}:
	default:
	}
}

func (e *Engine) audit(ctx context.Context, cap, outcome string, d map[string]any) {
	if err := e.Plat.Audit(ctx, cap, outcome, d); err != nil {
		e.Logf("heain-consent: audit %s %s: %v", cap, outcome, err)
	}
}

func (e *Engine) tell(ctx context.Context, to []string, kind, title, ref, sev string) {
	if len(to) == 0 {
		return
	}
	var out map[string]any
	if _, err := e.Plat.Call(ctx, heain.CallSpec{App: e.Cfg.NotifyApp, Capability: "notify.send", Method: http.MethodPost, Path: "/v1/messages",
		Body: map[string]any{"to": to, "kind": kind, "title": title, "ref": ref, "severity": sev}, Out: &out}); err != nil {
		e.Logf("heain-consent: telling %v (%s): %v", to, kind, err)
	}
}

// ---- purposes ----

// PurposeInput is a submitted purpose version.
type PurposeInput struct {
	Title          string   `json:"title"`
	Notice         string   `json:"notice"`
	LawfulBasis    string   `json:"lawful_basis"`
	DataCategories []string `json:"data_categories,omitempty"`
	Retention      string   `json:"retention,omitempty"`
	Reconsent      bool     `json:"requires_reconsent,omitempty"`
}

// Validate checks a purpose version.
func (p PurposeInput) Validate() error {
	switch {
	case strings.TrimSpace(p.Title) == "" || len(p.Title) > 120:
		return errors.New("title: 1 to 120 characters")
	case strings.TrimSpace(p.Notice) == "" || len(p.Notice) > 8000:
		return errors.New("notice: the text the person reads, 1 to 8000 characters")
	case !LawfulBases[p.LawfulBasis]:
		return errors.New("lawful_basis: consent, contract, legal_obligation, vital_interest, public_task or legitimate_interest")
	case len(p.DataCategories) > 50:
		return errors.New("data_categories: at most 50")
	}
	return nil
}

// SubmitPurpose stores a new version of a purpose and asks P5 to activate it.
func (e *Engine) SubmitPurpose(ctx context.Context, id string, in PurposeInput, by string) (store.PurposeVersion, error) {
	if err := in.Validate(); err != nil {
		return store.PurposeVersion{}, err
	}
	raw, _ := json.Marshal(in)
	h := sha256.Sum256(raw)
	e.mu.Lock()
	defer e.mu.Unlock()
	p, err := e.Store.Purpose(id)
	if errors.Is(err, store.ErrNotFound) {
		p = store.Purpose{ID: id}
	} else if err != nil {
		return store.PurposeVersion{}, err
	}
	v := store.PurposeVersion{N: len(p.Versions) + 1, Title: in.Title, Notice: in.Notice, LawfulBasis: in.LawfulBasis, DataCategories: in.DataCategories,
		Retention: in.Retention, Reconsent: in.Reconsent, SHA256: hex.EncodeToString(h[:]), By: by, At: e.Now().UTC(), State: "proposed"}
	r, err := e.Plat.Propose(ctx, heain.Proposal{Type: "consent.purpose.activate", Category: heain.CategoryKnowledgeUpdate,
		Data: map[string]any{"purpose": id, "version": v.N, "sha256": v.SHA256, "lawful_basis": v.LawfulBasis, "requires_reconsent": v.Reconsent, "submitted_by": by}})
	if err != nil {
		return store.PurposeVersion{}, fmt.Errorf("P5: %w", err)
	}
	v.ActionID = r.ActionID
	p.Versions = append(p.Versions, v)
	switch {
	case r.Allowed():
		e.activate(&p, v.N)
	case r.Result == heain.ResultDenied:
		p.Versions[len(p.Versions)-1].State = "denied"
	}
	if err := e.Store.PutPurpose(p); err != nil {
		return store.PurposeVersion{}, err
	}
	return p.Versions[len(p.Versions)-1], nil
}

func (e *Engine) activate(p *store.Purpose, n int) {
	for i := range p.Versions {
		switch {
		case p.Versions[i].N == n:
			p.Versions[i].State, p.Versions[i].DecidedAt = "active", e.Now().UTC()
		case p.Versions[i].State == "active":
			p.Versions[i].State = "retired"
		}
	}
	p.Active = n
}

func (e *Engine) pollPurposes(ctx context.Context) {
	for _, p := range e.Store.Purposes() {
		for _, v := range p.Versions {
			if v.State != "proposed" || v.ActionID == "" {
				continue
			}
			r, err := e.Plat.PolicyStatus(ctx, v.ActionID)
			if err != nil || r.Waiting() {
				continue
			}
			e.mu.Lock()
			cur, err := e.Store.Purpose(p.ID)
			if err == nil {
				if r.Allowed() {
					e.activate(&cur, v.N)
				} else {
					for i := range cur.Versions {
						if cur.Versions[i].N == v.N {
							cur.Versions[i].State, cur.Versions[i].DecidedAt = "denied", e.Now().UTC()
						}
					}
				}
				_ = e.Store.PutPurpose(cur)
			}
			e.mu.Unlock()
			e.audit(ctx, "consent.purpose", "version_"+map[bool]string{true: "activated", false: "denied"}[r.Allowed()],
				map[string]any{"purpose": p.ID, "version": v.N, "action_id": v.ActionID})
		}
	}
}

// ---- subjects and consent ----

// CleanIdentifiers validates and normalizes identifiers.
func CleanIdentifiers(ids []heain.SubjectIdentifier) ([]heain.SubjectIdentifier, error) {
	if len(ids) == 0 || len(ids) > 32 {
		return nil, errors.New("1 to 32 identifiers")
	}
	seen := map[string]bool{}
	var out []heain.SubjectIdentifier
	for _, id := range ids {
		v := heain.NormalizeIdentifier(id.Kind, id.Value)
		if !identKindOK(id.Kind) || v == "" || len(v) > 512 {
			return nil, fmt.Errorf("identifier %q: a kind ([a-z0-9_.-], or <app>:<kind>) and a value", id.Kind)
		}
		if id.Kind == heain.IdentEmail && !strings.Contains(v, "@") {
			return nil, errors.New("an email identifier needs an @")
		}
		if k := id.Kind + "\x00" + v; !seen[k] {
			seen[k] = true
			out = append(out, heain.SubjectIdentifier{Kind: id.Kind, Value: v})
		}
	}
	return out, nil
}

func identKindOK(k string) bool {
	if k == "" || len(k) > 127 {
		return false
	}
	parts := strings.Split(k, ":")
	if len(parts) > 2 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for i, r := range p {
			ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || (i > 0 && (r == '_' || r == '.' || r == '-'))
			if !ok {
				return false
			}
		}
	}
	return true
}

// RegisterSubject finds the subject the identifiers name and adds any new ones,
// or creates one. It returns the subject and whether it was created.
func (e *Engine) RegisterSubject(ctx context.Context, ids []heain.SubjectIdentifier) (store.Subject, bool, error) {
	ids, err := CleanIdentifiers(ids)
	if err != nil {
		return store.Subject{}, false, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.register(ctx, ids)
}

func (e *Engine) register(ctx context.Context, ids []heain.SubjectIdentifier) (store.Subject, bool, error) {
	id, err := e.Store.Find(ids)
	if err != nil {
		return store.Subject{}, false, err
	}
	now := e.Now().UTC()
	if id == "" {
		sub := store.Subject{ID: heain.NewID(), Identifiers: ids, Consents: []store.Consent{}, Created: now, Updated: now}
		return sub, true, e.Store.PutSubject(ctx, sub)
	}
	sub, err := e.Store.Subject(ctx, id)
	if err != nil {
		return store.Subject{}, false, err
	}
	changed := false
	for _, n := range ids {
		have := false
		for _, o := range sub.Identifiers {
			have = have || (o.Kind == n.Kind && o.Value == n.Value)
		}
		if !have {
			sub.Identifiers, changed = append(sub.Identifiers, n), true
		}
	}
	if changed {
		sub.Updated = now
		err = e.Store.PutSubject(ctx, sub)
	}
	return sub, false, err
}

// Record stores a person's decision about a purpose. version must be the
// purpose's active version (the notice the person saw).
func (e *Engine) Record(ctx context.Context, subjectID, purpose string, version int, given bool, by, channel, evidence string) (store.Consent, error) {
	p, err := e.Store.Purpose(purpose)
	if err != nil {
		return store.Consent{}, fmt.Errorf("no such purpose: %w", store.ErrNotFound)
	}
	av, ok := p.ActiveVersion()
	if !ok {
		return store.Consent{}, errors.New("the purpose has no active version (waiting for P5?)")
	}
	if given && version != av.N {
		return store.Consent{}, fmt.Errorf("consent is given to the active version %d (the notice shown), not %d", av.N, version)
	}
	if !given && version == 0 {
		version = av.N
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	sub, err := e.Store.Subject(ctx, subjectID)
	if err != nil {
		return store.Consent{}, err
	}
	c := store.Consent{Purpose: purpose, Version: version, Given: given, At: e.Now().UTC(), By: by, Channel: channel, Evidence: evidence}
	sub.Consents, sub.Updated = append(sub.Consents, c), c.At
	if err := e.Store.PutSubject(ctx, sub); err != nil {
		return store.Consent{}, err
	}
	e.audit(ctx, "consent.record", map[bool]string{true: "given", false: "withdrawn"}[given],
		map[string]any{"subject": sub.ID, "purpose": purpose, "version": version, "channel": channel})
	return c, nil
}

// Check is the answer apps get before processing for a purpose.
type Check struct {
	Purpose          string `json:"purpose"`
	Version          int    `json:"version"`
	LawfulBasis      string `json:"lawful_basis"`
	Allowed          bool   `json:"allowed"`
	ConsentedVersion int    `json:"consented_version,omitempty"`
	Reason           string `json:"reason"`
}

// CheckConsent answers whether a subject's data may be processed for a purpose.
func (e *Engine) CheckConsent(ctx context.Context, purpose, subjectID string, ids []heain.SubjectIdentifier) (Check, error) {
	p, err := e.Store.Purpose(purpose)
	if err != nil {
		return Check{}, fmt.Errorf("no such purpose: %w", store.ErrNotFound)
	}
	av, ok := p.ActiveVersion()
	if !ok {
		return Check{}, fmt.Errorf("purpose %s has no active version: %w", purpose, store.ErrNotFound)
	}
	c := Check{Purpose: purpose, Version: av.N, LawfulBasis: av.LawfulBasis}
	if subjectID == "" && len(ids) > 0 {
		if ids, err = CleanIdentifiers(ids); err != nil {
			return Check{}, err
		}
		if subjectID, err = e.Store.Find(ids); err != nil {
			return Check{}, err
		}
	}
	var sub store.Subject
	if subjectID != "" {
		if sub, err = e.Store.Subject(ctx, subjectID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return Check{}, err
		}
	}
	switch {
	case sub.Restricted:
		c.Reason = "restricted" // a restriction request stops all processing
	case av.LawfulBasis != "consent":
		c.Allowed, c.Reason = true, "lawful basis "+av.LawfulBasis
	default:
		l, ok := sub.Latest(purpose)
		switch {
		case !ok:
			c.Reason = "no consent recorded"
		case !l.Given:
			c.ConsentedVersion, c.Reason = l.Version, "consent withdrawn"
		case l.Version < p.ReconsentFrom():
			c.ConsentedVersion, c.Reason = l.Version, fmt.Sprintf("consent to version %d no longer counts: version %d needs it again", l.Version, p.ReconsentFrom())
		default:
			c.Allowed, c.ConsentedVersion, c.Reason = true, l.Version, "consent given"
		}
	}
	return c, nil
}

// ---- requests ----

// File opens a data-subject request.
func (e *Engine) File(ctx context.Context, subjectID, typ, note string, purposes []string, by, channel string) (store.Request, error) {
	if !RequestTypes[typ] {
		return store.Request{}, errors.New("type: access, portability, erasure, rectification, restriction or objection")
	}
	if len(note) > 2000 {
		return store.Request{}, errors.New("note: at most 2000 characters")
	}
	for _, p := range purposes {
		if _, err := e.Store.Purpose(p); err != nil {
			return store.Request{}, fmt.Errorf("no such purpose %s", p)
		}
	}
	if _, err := e.Store.Subject(ctx, subjectID); err != nil {
		return store.Request{}, err
	}
	now := e.Now().UTC()
	r := store.Request{ID: heain.NewID(), Subject: subjectID, Type: typ, Status: StReceived, Note: note, Purposes: purposes, By: by, Channel: channel,
		Created: now, Due: now.Add(e.Cfg.Due), History: []store.Event{{At: now, What: "received", Who: by, Detail: map[string]any{"channel": channel}}}}
	e.mu.Lock()
	err := e.Store.PutRequest(ctx, r)
	e.mu.Unlock()
	if err != nil {
		return store.Request{}, err
	}
	e.audit(ctx, "consent.request", "received", map[string]any{"request": r.ID, "subject": subjectID, "type": typ, "channel": channel, "due": r.Due})
	e.tell(ctx, []string{"group:" + e.Cfg.DPOGroup}, "consent.request", "Data-subject request ("+typ+") to verify", r.ID, "info")
	return r, nil
}

// ErrState: the request is not in a state that allows this.
var ErrState = errors.New("the request is not in a state that allows this")

// Verify is the DPO's decision about the person's identity. ids are
// identifiers the DPO verified and adds to the subject.
func (e *Engine) Verify(ctx context.Context, id string, ok bool, note, dpo string, ids []heain.SubjectIdentifier) (store.Request, error) {
	var err error
	if len(ids) > 0 {
		if ids, err = CleanIdentifiers(ids); err != nil {
			return store.Request{}, err
		}
	}
	e.mu.Lock()
	r, err := e.Store.Request(ctx, id)
	if err != nil {
		e.mu.Unlock()
		return r, err
	}
	if r.Status != StReceived {
		e.mu.Unlock()
		return r, ErrState
	}
	now := e.Now().UTC()
	if ok && len(ids) > 0 {
		if other, err := e.Store.Find(ids); err != nil || (other != "" && other != r.Subject) {
			e.mu.Unlock()
			return r, store.ErrConflict
		}
		sub, err := e.Store.Subject(ctx, r.Subject)
		if err == nil {
			ids = append(sub.Identifiers, ids...)
			_, _, err = e.register(ctx, ids)
		}
		if err != nil {
			e.mu.Unlock()
			return r, err
		}
	}
	if ok {
		r.Status = StVerified
		if r.Type == "rectification" || r.Type == "restriction" || r.Type == "objection" {
			r.Status = StInProgress
		}
		r.History = append(r.History, store.Event{At: now, What: "verified", Who: dpo, Detail: map[string]any{"note": note, "identifiers_added": len(ids)}})
	} else {
		r.Status, r.Closed, r.Outcome = StRejected, now, "the identity could not be verified"
		r.History = append(r.History, store.Event{At: now, What: "rejected", Who: dpo, Detail: map[string]any{"note": note}})
	}
	err = e.Store.PutRequest(ctx, r)
	e.mu.Unlock()
	if err != nil {
		return r, err
	}
	e.audit(ctx, "consent.request", map[bool]string{true: "verified", false: "rejected"}[ok], map[string]any{"request": r.ID, "type": r.Type, "by": dpo})
	if !ok {
		e.tellSubject(ctx, r, "consent.request.closed", "Your request ("+r.Type+") was not accepted")
	}
	e.wake()
	return r, nil
}

// Complete finishes a request a DPO carries out (rectification, restriction,
// objection). withdraw names purposes whose consent ends (objection); restrict
// stops all processing for the person (restriction).
func (e *Engine) Complete(ctx context.Context, id, note, dpo string, withdraw []string, restrict *bool) (store.Request, error) {
	e.mu.Lock()
	r, err := e.Store.Request(ctx, id)
	if err != nil {
		e.mu.Unlock()
		return r, err
	}
	if r.Status != StInProgress {
		e.mu.Unlock()
		return r, ErrState
	}
	sub, err := e.Store.Subject(ctx, r.Subject)
	if err != nil {
		e.mu.Unlock()
		return r, err
	}
	now := e.Now().UTC()
	for _, p := range withdraw {
		pp, err := e.Store.Purpose(p)
		if err != nil {
			e.mu.Unlock()
			return r, fmt.Errorf("no such purpose %s", p)
		}
		sub.Consents = append(sub.Consents, store.Consent{Purpose: p, Version: pp.Active, Given: false, At: now, By: dpo, Channel: "dpo", Evidence: "request " + r.ID})
	}
	if restrict != nil {
		sub.Restricted = *restrict
	}
	sub.Updated = now
	if err := e.Store.PutSubject(ctx, sub); err != nil {
		e.mu.Unlock()
		return r, err
	}
	r.Status, r.Closed, r.Outcome = StCompleted, now, note
	r.History = append(r.History, store.Event{At: now, What: "completed", Who: dpo, Detail: map[string]any{"withdrawn": withdraw, "restricted": sub.Restricted}})
	err = e.Store.PutRequest(ctx, r)
	e.mu.Unlock()
	if err != nil {
		return r, err
	}
	for _, p := range withdraw {
		e.audit(ctx, "consent.record", "withdrawn", map[string]any{"subject": sub.ID, "purpose": p, "channel": "dpo", "request": r.ID})
	}
	e.audit(ctx, "consent.request", "completed", map[string]any{"request": r.ID, "type": r.Type, "by": dpo, "restricted": sub.Restricted})
	e.tellSubject(ctx, r, "consent.request.closed", "Your request ("+r.Type+") was completed")
	return r, nil
}

// tellSubject tells the person (their heain-gateway account, if known).
func (e *Engine) tellSubject(ctx context.Context, r store.Request, kind, title string) {
	sub, err := e.Store.Subject(ctx, r.Subject)
	if err != nil {
		return
	}
	e.tell(ctx, gatewayTargets(sub), kind, title, r.ID, "info")
}

func gatewayTargets(sub store.Subject) []string {
	var to []string
	for _, id := range sub.Identifiers {
		if id.Kind == heain.IdentGatewayUser {
			to = append(to, "gateway_user:"+id.Value)
		}
	}
	return to
}

// ---- the engine loop ----

// Run drives requests, P5 decisions, deadlines and bundle expiry.
func (e *Engine) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-e.kick:
		}
		e.Tick(ctx)
	}
}

// Tick does one round.
func (e *Engine) Tick(ctx context.Context) {
	now := e.Now()
	poll := now.Sub(e.last) >= e.Cfg.PollEvery
	if poll {
		e.last = now
		e.pollPurposes(ctx)
	}
	for _, ref := range e.Store.RequestRefs() {
		if Closed(ref.Status) {
			continue
		}
		switch ref.Status {
		case StReceived, StInProgress:
			e.deadline(ctx, ref)
		case StAwaitingApproval, StAwaitingOverride:
			e.deadline(ctx, ref)
			if poll {
				e.advance(ctx, ref.ID)
			}
		default:
			e.deadline(ctx, ref)
			e.advance(ctx, ref.ID)
		}
	}
	for _, id := range e.Store.ExpiredBundles(now) {
		if err := e.Store.ShredBundle(ctx, id); err == nil {
			e.audit(ctx, "consent.request", "export_expired", map[string]any{"bundle": id})
		}
	}
}

func (e *Engine) deadline(ctx context.Context, ref store.RequestRef) {
	now := e.Now()
	var mark, title, sev string
	switch {
	case now.After(ref.Due):
		mark, title, sev = "overdue", "Data-subject request overdue", "critical"
	case now.After(ref.Due.Add(-e.Cfg.RemindBefore)):
		mark, title, sev = "due_soon", "Data-subject request due soon", "warning"
	default:
		return
	}
	e.mu.Lock()
	r, err := e.Store.Request(ctx, ref.ID)
	if err != nil || Closed(r.Status) {
		e.mu.Unlock()
		return
	}
	for _, m := range r.Reminded {
		if m == mark {
			e.mu.Unlock()
			return
		}
	}
	r.Reminded = append(r.Reminded, mark)
	r.History = append(r.History, store.Event{At: now.UTC(), What: mark})
	_ = e.Store.PutRequest(ctx, r)
	e.mu.Unlock()
	e.tell(ctx, []string{"group:" + e.Cfg.DPOGroup}, "consent.request."+mark, title+" ("+r.Type+", "+r.Due.Format("2006-01-02")+")", r.ID, sev)
	e.audit(ctx, "consent.request", mark, map[string]any{"request": r.ID, "type": r.Type, "due": r.Due, "status": r.Status})
}

// advance moves one request as far as it can go now. The calls to apps are
// made without the lock; only this loop changes requests in these states.
func (e *Engine) advance(ctx context.Context, id string) {
	r, err := e.Store.Request(ctx, id)
	if err != nil {
		return
	}
	sub, err := e.Store.Subject(ctx, r.Subject)
	if err != nil {
		e.Logf("heain-consent: request %s: subject: %v", r.ID, err)
		return
	}
	now := e.Now().UTC()
	before := r.Status
	switch r.Status {
	case StVerified:
		switch r.Type {
		case "access", "portability":
			r.Status = StCollecting
		case "erasure":
			r.Status = StPlanning
		}
	case StCollecting:
		var done bool
		r.Results, r.Collected, done = e.collect(ctx, r, sub)
		if done {
			b, err := e.bundle(ctx, r, sub)
			if err != nil {
				e.Logf("heain-consent: request %s: bundle: %v", r.ID, err)
				return
			}
			r.Bundle, r.Collected = b.ID, nil
			r.Status, r.Closed, r.Outcome = StCompleted, now, fmt.Sprintf("an export of %d app instance(s), signed, available until %s", len(r.Results), b.Expires.Format("2006-01-02"))
		}
	case StPlanning:
		var done bool
		if r.Plan, done = e.erase(ctx, r, sub, r.Plan, true, ""); done {
			er, held := totals(r.Plan)
			res, err := e.Plat.Propose(ctx, heain.Proposal{Type: "consent.erasure", Category: heain.CategoryAllowlist,
				Data: map[string]any{"request": r.ID, "subject": r.Subject, "instances": len(r.Plan), "items_to_erase": er, "items_held": held, "reasons": reasons(r.Plan)}})
			if err != nil {
				e.Logf("heain-consent: request %s: P5: %v", r.ID, err)
				return
			}
			r.ActionID, r.Status = res.ActionID, StAwaitingApproval
			e.decided(&r, res, StErasing)
		}
	case StAwaitingApproval:
		res, err := e.Plat.PolicyStatus(ctx, r.ActionID)
		if err != nil {
			return
		}
		e.decided(&r, res, StErasing)
	case StErasing:
		var done bool
		if r.Results, done = e.erase(ctx, r, sub, r.Results, false, ""); done {
			if _, held := totals(r.Results); held > 0 {
				res, err := e.Plat.Propose(ctx, heain.Proposal{Type: "consent.erasure.override", Category: heain.CategoryRetentionOverride,
					Data: map[string]any{"request": r.ID, "subject": r.Subject, "items_held": held, "reasons": reasons(r.Results)}})
				if err != nil {
					e.Logf("heain-consent: request %s: P5: %v", r.ID, err)
					return
				}
				r.Override, r.Status = res.ActionID, StAwaitingOverride
				if e.decided(&r, res, StErasingOverride); r.Status == StErasingOverride {
					overridePass(r.Results)
				}
			} else {
				e.finishErasure(ctx, &r, sub, true)
			}
		}
	case StAwaitingOverride:
		res, err := e.Plat.PolicyStatus(ctx, r.Override)
		if err != nil {
			return
		}
		if e.decided(&r, res, StErasingOverride); r.Status == StErasingOverride {
			overridePass(r.Results)
		}
		if r.Status == StRefused { // the override was denied: what is held stays, the rest is gone
			r.Status = StErasing
			e.finishErasure(ctx, &r, sub, false)
		}
	case StErasingOverride:
		var done bool
		if r.Results, done = e.erase(ctx, r, sub, r.Results, false, r.Override); done {
			_, held := totals(r.Results)
			e.finishErasure(ctx, &r, sub, held == 0)
		}
	default:
		return
	}
	if r.Status != before {
		r.History = append(r.History, store.Event{At: now, What: r.Status})
	}
	e.mu.Lock()
	cur, err := e.Store.Request(ctx, id)
	if err == nil && cur.Status == before {
		err = e.Store.PutRequest(ctx, r)
	}
	e.mu.Unlock()
	if err != nil {
		e.Logf("heain-consent: request %s: %v", r.ID, err)
		return
	}
	if r.Status != before {
		e.audit(ctx, "consent.request", r.Status, map[string]any{"request": r.ID, "type": r.Type, "action_id": r.ActionID, "override_id": r.Override})
		if Closed(r.Status) && r.Status != StCompletedHolds && (r.Type != "erasure" || r.Status == StRefused) {
			e.tellSubject(ctx, r, "consent.request.closed", "Your request ("+r.Type+") is "+strings.ReplaceAll(r.Status, "_", " "))
		}
		e.wake()
	}
}

// decided applies a P5 result: allowed → next; denied → refused.
func (e *Engine) decided(r *store.Request, res heain.PolicyResult, next string) {
	switch {
	case res.Waiting():
	case res.Allowed():
		r.Status = next
	default:
		r.Status, r.Closed, r.Outcome = StRefused, e.Now().UTC(), "the Approver denied it (P5)"
	}
}

// finishErasure ends an erasure: when nothing is held anywhere, the
// subject's own record here is shredded too; otherwise their consents are
// withdrawn and the record stays for what is held.
func (e *Engine) finishErasure(ctx context.Context, r *store.Request, sub store.Subject, all bool) {
	now := e.Now().UTC()
	to := gatewayTargets(sub)
	er, held := totals(r.Results)
	errs := 0
	for _, x := range r.Results {
		if x.Status == "error" {
			errs++
		}
	}
	e.mu.Lock()
	if all && errs == 0 {
		if err := e.Store.ShredSubject(ctx, sub); err != nil {
			e.mu.Unlock()
			e.Logf("heain-consent: request %s: shredding the subject: %v", r.ID, err)
			return
		}
		r.Status, r.Outcome = StCompleted, fmt.Sprintf("%d item(s) erased in %d app instance(s); the person's record here was shredded", er, len(r.Results))
	} else {
		if cur, err := e.Store.Subject(ctx, sub.ID); err == nil {
			for _, p := range e.Store.Purposes() {
				if l, ok := cur.Latest(p.ID); ok && l.Given {
					cur.Consents = append(cur.Consents, store.Consent{Purpose: p.ID, Version: l.Version, Given: false, At: now, By: e.Cfg.Self, Channel: "dpo", Evidence: "erasure " + r.ID})
				}
			}
			cur.Updated = now
			_ = e.Store.PutSubject(ctx, cur)
		}
		r.Status = StCompletedHolds
		r.Outcome = fmt.Sprintf("%d item(s) erased; %d held (%s); %d instance(s) failed", er, held, strings.Join(reasons(r.Results), ", "), errs)
	}
	e.mu.Unlock()
	r.Closed = now
	e.tell(ctx, to, "consent.request.closed", "Your erasure request is "+strings.ReplaceAll(r.Status, "_", " "), r.ID, "info")
}

func totals(rs []store.AppResult) (erased, held int) {
	for _, x := range rs {
		erased += len(x.Erased)
		held += len(x.Held)
	}
	return
}

func reasons(rs []store.AppResult) []string {
	m := map[string]bool{}
	for _, x := range rs {
		for _, h := range x.Held {
			m[h.Reason] = true
		}
	}
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// targets are the live instances that declare subject.rights (not this app).
func (e *Engine) targets(ctx context.Context) ([]heain.Instance, error) {
	insts, err := e.Plat.Discover(ctx, heain.SubjectRightsCapability, 1)
	if err != nil {
		return nil, err
	}
	var out []heain.Instance
	for _, in := range insts {
		if in.AppID != e.Cfg.Self && in.Execution == "direct" && in.EndpointBase != "" {
			out = append(out, in)
		}
	}
	return out, nil
}

// each calls f for every target instance whose result is not final yet,
// and reports whether all are final.
func (e *Engine) each(ctx context.Context, prev []store.AppResult, f func(in heain.Instance, res *store.AppResult) error) ([]store.AppResult, bool) {
	insts, err := e.targets(ctx)
	if err != nil {
		e.Logf("heain-consent: discover: %v", err)
		return prev, false
	}
	byKey := map[string]int{}
	out := append([]store.AppResult(nil), prev...)
	for i, x := range out {
		byKey[x.App+"."+x.Instance] = i
	}
	live := map[string]bool{}
	for _, in := range insts {
		k := in.AppID + "." + in.InstanceID
		live[k] = true
		if _, ok := byKey[k]; !ok {
			byKey[k] = len(out)
			out = append(out, store.AppResult{App: in.AppID, Instance: in.InstanceID, Status: "pending"})
		}
		res := &out[byKey[k]]
		if res.Status != "pending" {
			continue
		}
		if err := f(in, res); err != nil {
			res.Attempts++
			res.Error = trim(err.Error(), 200)
			if res.Attempts >= e.Cfg.MaxAttempts {
				res.Status = "error"
			}
			continue
		}
		res.Status, res.Error = "ok", ""
	}
	done := true
	for i := range out {
		if out[i].Status == "pending" && !live[out[i].App+"."+out[i].Instance] {
			out[i].Attempts++
			out[i].Error = "no live instance"
			if out[i].Attempts >= e.Cfg.MaxAttempts {
				out[i].Status = "error"
			}
		}
		if out[i].Status == "pending" {
			done = false
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].App+out[i].Instance < out[j].App+out[j].Instance })
	return out, done
}

func (e *Engine) subjectRequest(r store.Request, sub store.Subject) heain.SubjectRequest {
	return heain.SubjectRequest{Request: r.ID, Subject: r.Subject, Identifiers: sub.Identifiers}
}

func (e *Engine) collect(ctx context.Context, r store.Request, sub store.Subject) ([]store.AppResult, []store.AppExport, bool) {
	got := r.Collected
	out, done := e.each(ctx, r.Results, func(in heain.Instance, res *store.AppResult) error {
		var x heain.SubjectExport
		if _, err := e.Plat.Call(ctx, heain.CallSpec{App: in.AppID, Instance: in.InstanceID, Capability: heain.SubjectRightsCapability, Version: 1,
			Method: http.MethodPost, Path: heain.SubjectRightsExportPath, Body: e.subjectRequest(r, sub), Out: &x, Timeout: 60 * time.Second}); err != nil {
			return err
		}
		res.Items = len(x.Items)
		got = append(got, store.AppExport{App: in.AppID, Instance: in.InstanceID, Items: x.Items})
		return nil
	})
	return out, got, done
}

func (e *Engine) erase(ctx context.Context, r store.Request, sub store.Subject, prev []store.AppResult, dry bool, override string) ([]store.AppResult, bool) {
	return e.each(ctx, prev, func(in heain.Instance, res *store.AppResult) error {
		q := e.subjectRequest(r, sub)
		q.DryRun, q.Override = dry, override
		var x heain.SubjectErasure
		if _, err := e.Plat.Call(ctx, heain.CallSpec{App: in.AppID, Instance: in.InstanceID, Capability: heain.SubjectRightsCapability, Version: 1,
			Method: http.MethodPost, Path: heain.SubjectRightsErasePath, Body: q, Out: &x, Timeout: 60 * time.Second}); err != nil {
			return err
		}
		if override != "" {
			res.Erased = append(res.Erased, x.Erased...) // the second pass adds what was held
		} else {
			res.Erased = x.Erased
		}
		res.Held = x.Held
		return nil
	})
}

// overridePass makes the instances that held something pending again, for
// the pass under an approved RETENTION_OVERRIDE.
func overridePass(rs []store.AppResult) {
	for i := range rs {
		if len(rs[i].Held) > 0 {
			rs[i].Status, rs[i].Attempts, rs[i].Error = "pending", 0, ""
		}
	}
}

// ExportBody is the signed export.
type ExportBody struct {
	Format      string                    `json:"format"`
	Request     string                    `json:"request"`
	Type        string                    `json:"type"`
	Subject     string                    `json:"subject"`
	Generated   time.Time                 `json:"generated"`
	Identifiers []heain.SubjectIdentifier `json:"identifiers"`
	Consents    []store.Consent           `json:"consents"`
	Apps        []store.AppExport         `json:"apps"`
}

func (e *Engine) bundle(ctx context.Context, r store.Request, sub store.Subject) (store.Bundle, error) {
	apps := append([]store.AppExport{}, r.Collected...)
	sort.Slice(apps, func(i, j int) bool { return apps[i].App+apps[i].Instance < apps[j].App+apps[j].Instance })
	body, err := json.Marshal(ExportBody{Format: "heain-consent-export/1", Request: r.ID, Type: r.Type, Subject: sub.ID, Generated: e.Now().UTC(),
		Identifiers: sub.Identifiers, Consents: sub.Consents, Apps: apps})
	if err != nil {
		return store.Bundle{}, err
	}
	h := sha256.Sum256(body)
	sig, err := e.Plat.SignDigest(h[:])
	if err != nil {
		return store.Bundle{}, err
	}
	b := store.Bundle{ID: heain.NewID(), Request: r.ID, Body: body, SHA256: hex.EncodeToString(h[:]), Signature: sig, Cert: e.Plat.CertDER(),
		Expires: e.Now().Add(e.Cfg.BundleTTL).UTC()}
	e.mu.Lock()
	err = e.Store.PutBundle(ctx, b)
	e.mu.Unlock()
	return b, err
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
