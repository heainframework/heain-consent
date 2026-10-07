// Package store keeps heain-consent's state in BoltDB, sealed under data
// keys held by heain-core's KMS: purposes under the app's inside key; each
// data subject (identifiers and consent history) under its own key, and each
// request and each export bundle under their own keys, so erasing a person,
// or letting an export expire, is a crypto-shred. Identifiers are indexed by
// HMAC, never stored in the clear.
package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/heainframework/heain-sdk/heain"
	bolt "go.etcd.io/bbolt"
)

var (
	bPurposes = []byte("purposes")
	bSubjects = []byte("subjects")
	bIndex    = []byte("index")
	bRequests = []byte("requests")
	bBundles  = []byte("bundles")
)

// ErrNotFound: no such record.
var ErrNotFound = errors.New("not found")

// ErrConflict: identifiers that belong to different subjects.
var ErrConflict = errors.New("these identifiers belong to different subjects")

// Keys gives per-record keys (core's KMS).
type Keys struct {
	Sealer  func(ctx context.Context, name string) (*heain.Sealer, error)
	Destroy func(ctx context.Context, name string) error
}

// Store is the sealed state.
type Store struct {
	db     *bolt.DB
	inside *heain.Sealer
	ixKey  []byte
	keys   Keys
}

// Open opens (creating) the store.
func Open(path string, inside []byte, keys Keys) (*Store, error) {
	s, err := heain.NewSealer(inside)
	if err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bPurposes, bSubjects, bIndex, bRequests, bBundles} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, err
	}
	m := hmac.New(sha256.New, inside)
	m.Write([]byte("heain-consent/index"))
	return &Store{db: db, inside: s, ixKey: m.Sum(nil), keys: keys}, nil
}

// Close closes the store.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) ix(kind, id string) string {
	m := hmac.New(sha256.New, s.ixKey)
	m.Write([]byte(kind + "\x00" + id))
	return hex.EncodeToString(m.Sum(nil))
}

func (s *Store) put(b []byte, kind, id string, v any) error {
	k := s.ix(kind, id)
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(b).Put([]byte(k), s.inside.Seal(raw, []byte(kind+"/"+k))) })
}

func (s *Store) get(b []byte, kind, id string, v any) error {
	k := s.ix(kind, id)
	var sealed []byte
	_ = s.db.View(func(tx *bolt.Tx) error {
		if x := tx.Bucket(b).Get([]byte(k)); x != nil {
			sealed = append([]byte(nil), x...)
		}
		return nil
	})
	if sealed == nil {
		return ErrNotFound
	}
	raw, err := s.inside.Open(sealed, []byte(kind+"/"+k))
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func (s *Store) each(b []byte, kind string, f func(raw []byte)) {
	type kv struct{ k, v []byte }
	var all []kv
	_ = s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(b).ForEach(func(k, v []byte) error {
			all = append(all, kv{append([]byte(nil), k...), append([]byte(nil), v...)})
			return nil
		})
	})
	for _, x := range all {
		if raw, err := s.inside.Open(x.v, []byte(kind+"/"+string(x.k))); err == nil {
			f(raw)
		}
	}
}

// envelope is a record sealed under its own key; the fields beside Sealed
// are what the engine scans without opening it.
type envelope struct {
	ID     string    `json:"id"`
	Key    string    `json:"key"`
	Sealed []byte    `json:"sealed,omitempty"`
	Status string    `json:"status,omitempty"`
	Due    time.Time `json:"due,omitempty"`
	Gone   bool      `json:"gone,omitempty"` // the key was destroyed
}

func (s *Store) putOwn(ctx context.Context, b []byte, kind, id string, v any, env envelope) error {
	env.ID, env.Key = id, kind+"-"+s.ix(kind, id)[:24]
	ks, err := s.keys.Sealer(ctx, env.Key)
	if err != nil {
		return fmt.Errorf("%s key: %w", kind, err)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	env.Sealed = ks.Seal(raw, []byte(kind+"/"+id))
	return s.put(b, kind, id, env)
}

func (s *Store) getOwn(ctx context.Context, b []byte, kind, id string, v any) (envelope, error) {
	var env envelope
	if err := s.get(b, kind, id, &env); err != nil {
		return env, err
	}
	if env.Gone {
		return env, ErrNotFound
	}
	ks, err := s.keys.Sealer(ctx, env.Key)
	if err != nil {
		return env, fmt.Errorf("%s key: %w", kind, err)
	}
	raw, err := ks.Open(env.Sealed, []byte(kind+"/"+id))
	if err != nil {
		return env, err
	}
	return env, json.Unmarshal(raw, v)
}

// shred destroys a record's key and leaves a tombstone.
func (s *Store) shred(ctx context.Context, b []byte, kind, id string) error {
	var env envelope
	if err := s.get(b, kind, id, &env); err != nil {
		return err
	}
	if err := s.keys.Destroy(ctx, env.Key); err != nil {
		return fmt.Errorf("destroying the %s key: %w", kind, err)
	}
	return s.put(b, kind, id, envelope{ID: id, Key: env.Key, Gone: true})
}

// ---- purposes ----

// PurposeVersion is one submitted version of a purpose.
type PurposeVersion struct {
	N              int       `json:"n"`
	Title          string    `json:"title"`
	Notice         string    `json:"notice"`       // the text the person reads
	LawfulBasis    string    `json:"lawful_basis"` // consent | contract | legal_obligation | vital_interest | public_task | legitimate_interest
	DataCategories []string  `json:"data_categories,omitempty"`
	Retention      string    `json:"retention,omitempty"`
	Reconsent      bool      `json:"requires_reconsent,omitempty"` // earlier consents no longer count
	SHA256         string    `json:"sha256"`
	By             string    `json:"by"`
	At             time.Time `json:"at"`
	State          string    `json:"state"` // proposed | active | retired | denied
	ActionID       string    `json:"action_id,omitempty"`
	DecidedAt      time.Time `json:"decided_at,omitempty"`
}

// Purpose is a purpose of processing with its versions.
type Purpose struct {
	ID       string           `json:"id"`
	Active   int              `json:"active"` // 0 = none yet
	Versions []PurposeVersion `json:"versions"`
}

// ActiveVersion returns the active version.
func (p Purpose) ActiveVersion() (PurposeVersion, bool) {
	for _, v := range p.Versions {
		if v.N == p.Active {
			return v, true
		}
	}
	return PurposeVersion{}, false
}

// ReconsentFrom is the lowest version a consent must be for to count.
func (p Purpose) ReconsentFrom() int {
	from := 1
	for _, v := range p.Versions {
		if v.Reconsent && v.N <= p.Active && (v.State == "active" || v.State == "retired") && v.N > from {
			from = v.N
		}
	}
	return from
}

// PutPurpose stores a purpose.
func (s *Store) PutPurpose(p Purpose) error { return s.put(bPurposes, "purpose", p.ID, p) }

// Purpose reads one.
func (s *Store) Purpose(id string) (Purpose, error) {
	var p Purpose
	return p, s.get(bPurposes, "purpose", id, &p)
}

// Purposes lists them.
func (s *Store) Purposes() []Purpose {
	out := []Purpose{}
	s.each(bPurposes, "purpose", func(raw []byte) {
		var p Purpose
		if json.Unmarshal(raw, &p) == nil {
			out = append(out, p)
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ---- subjects ----

// Consent is one decision of a person about a purpose.
type Consent struct {
	Purpose  string    `json:"purpose"`
	Version  int       `json:"version"`
	Given    bool      `json:"given"`
	At       time.Time `json:"at"`
	By       string    `json:"by"`      // the person (gateway account), a DPO, or the recording app
	Channel  string    `json:"channel"` // self | app | dpo
	Evidence string    `json:"evidence,omitempty"`
}

// Subject is a data subject.
type Subject struct {
	ID          string                    `json:"id"`
	Identifiers []heain.SubjectIdentifier `json:"identifiers"`
	Consents    []Consent                 `json:"consents"` // the history, oldest first
	Restricted  bool                      `json:"restricted,omitempty"`
	Created     time.Time                 `json:"created"`
	Updated     time.Time                 `json:"updated"`
}

// Latest returns the latest decision about purpose.
func (s Subject) Latest(purpose string) (Consent, bool) {
	for i := len(s.Consents) - 1; i >= 0; i-- {
		if s.Consents[i].Purpose == purpose {
			return s.Consents[i], true
		}
	}
	return Consent{}, false
}

func identKey(id heain.SubjectIdentifier) string {
	return id.Kind + "\x00" + heain.NormalizeIdentifier(id.Kind, id.Value)
}

// PutSubject stores a subject under its own key and indexes its identifiers.
func (s *Store) PutSubject(ctx context.Context, sub Subject) error {
	if err := s.putOwn(ctx, bSubjects, "subj", sub.ID, sub, envelope{}); err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, id := range sub.Identifiers {
			if err := tx.Bucket(bIndex).Put([]byte(s.ix("ident", identKey(id))), []byte(sub.ID)); err != nil {
				return err
			}
		}
		return nil
	})
}

// Subject reads one.
func (s *Store) Subject(ctx context.Context, id string) (Subject, error) {
	var sub Subject
	_, err := s.getOwn(ctx, bSubjects, "subj", id, &sub)
	return sub, err
}

// Find returns the one subject any of ids names ("" when none).
func (s *Store) Find(ids []heain.SubjectIdentifier) (string, error) {
	found := ""
	err := s.db.View(func(tx *bolt.Tx) error {
		for _, id := range ids {
			if v := tx.Bucket(bIndex).Get([]byte(s.ix("ident", identKey(id)))); v != nil {
				if found != "" && found != string(v) {
					return ErrConflict
				}
				found = string(v)
			}
		}
		return nil
	})
	return found, err
}

// ShredSubject removes a subject: its identifiers from the index, then its key.
func (s *Store) ShredSubject(ctx context.Context, sub Subject) error {
	if err := s.db.Update(func(tx *bolt.Tx) error {
		for _, id := range sub.Identifiers {
			if err := tx.Bucket(bIndex).Delete([]byte(s.ix("ident", identKey(id)))); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return s.shred(ctx, bSubjects, "subj", sub.ID)
}

// ---- requests ----

// AppResult is one app instance's part of a request.
type AppResult struct {
	App      string              `json:"app"`
	Instance string              `json:"instance"`
	Status   string              `json:"status"` // pending | ok | error
	Erased   []heain.SubjectItem `json:"erased,omitempty"`
	Held     []heain.SubjectItem `json:"held,omitempty"`
	Items    int                 `json:"items,omitempty"` // export: how many
	Attempts int                 `json:"attempts,omitempty"`
	Error    string              `json:"error,omitempty"`
}

// AppExport is one app instance's export answer.
type AppExport struct {
	App      string              `json:"app"`
	Instance string              `json:"instance"`
	Items    []heain.SubjectItem `json:"items"`
}

// Event is one line of a request's history.
type Event struct {
	At     time.Time      `json:"at"`
	What   string         `json:"what"`
	Who    string         `json:"who,omitempty"`
	Detail map[string]any `json:"detail,omitempty"`
}

// Request is a data-subject request.
type Request struct {
	ID        string      `json:"id"`
	Subject   string      `json:"subject"`
	Type      string      `json:"type"`   // access | portability | erasure | rectification | restriction | objection
	Status    string      `json:"status"` // see the engine
	Note      string      `json:"note,omitempty"`
	Purposes  []string    `json:"purposes,omitempty"` // objection: which purposes
	By        string      `json:"by"`                 // who filed it
	Channel   string      `json:"channel"`            // self | app | dpo
	Created   time.Time   `json:"created"`
	Due       time.Time   `json:"due"`
	Closed    time.Time   `json:"closed,omitempty"`
	Outcome   string      `json:"outcome,omitempty"`
	ActionID  string      `json:"action_id,omitempty"`   // P5: the erasure
	Override  string      `json:"override_id,omitempty"` // P5: RETENTION_OVERRIDE for what is held
	Plan      []AppResult `json:"plan,omitempty"`        // erasure: the dry run
	Results   []AppResult `json:"results,omitempty"`
	Bundle    string      `json:"bundle,omitempty"`    // export: the bundle id
	Collected []AppExport `json:"collected,omitempty"` // export: answers so far (until the bundle is made)
	Reminded  []string    `json:"reminded,omitempty"`
	History   []Event     `json:"history"`
}

// PutRequest stores a request under its own key.
func (s *Store) PutRequest(ctx context.Context, r Request) error {
	return s.putOwn(ctx, bRequests, "req", r.ID, r, envelope{Status: r.Status, Due: r.Due})
}

// Request reads one.
func (s *Store) Request(ctx context.Context, id string) (Request, error) {
	var r Request
	_, err := s.getOwn(ctx, bRequests, "req", id, &r)
	return r, err
}

// RequestRef is what can be read of a request without its key.
type RequestRef struct {
	ID     string
	Status string
	Due    time.Time
}

// RequestRefs lists every request.
func (s *Store) RequestRefs() []RequestRef {
	var out []RequestRef
	s.each(bRequests, "req", func(raw []byte) {
		var env envelope
		if json.Unmarshal(raw, &env) == nil && !env.Gone {
			out = append(out, RequestRef{env.ID, env.Status, env.Due})
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ---- export bundles ----

// Bundle is a signed export.
type Bundle struct {
	ID        string    `json:"id"`
	Request   string    `json:"request"`
	Body      []byte    `json:"body"` // the canonical JSON that was signed
	SHA256    string    `json:"sha256"`
	Signature []byte    `json:"signature"`
	Cert      []byte    `json:"cert"` // DER of the signing app certificate
	Expires   time.Time `json:"expires"`
}

// PutBundle stores a bundle under its own key.
func (s *Store) PutBundle(ctx context.Context, b Bundle) error {
	return s.putOwn(ctx, bBundles, "bundle", b.ID, b, envelope{Due: b.Expires})
}

// Bundle reads one.
func (s *Store) Bundle(ctx context.Context, id string) (Bundle, error) {
	var b Bundle
	_, err := s.getOwn(ctx, bBundles, "bundle", id, &b)
	return b, err
}

// ExpiredBundles lists bundles past their expiry that still have a key.
func (s *Store) ExpiredBundles(now time.Time) []string {
	var out []string
	s.each(bBundles, "bundle", func(raw []byte) {
		var env envelope
		if json.Unmarshal(raw, &env) == nil && !env.Gone && now.After(env.Due) {
			out = append(out, env.ID)
		}
	})
	return out
}

// ShredBundle destroys a bundle's key.
func (s *Store) ShredBundle(ctx context.Context, id string) error {
	return s.shred(ctx, bBundles, "bundle", id)
}
