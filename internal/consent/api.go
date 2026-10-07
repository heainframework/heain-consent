package consent

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/heainframework/heain-consent/internal/store"
	"github.com/heainframework/heain-sdk/heain"
)

// App-plane API (mTLS, served by heain-sdk). The endpoints people use are
// declared public, so heain-gateway may expose them (through P5):
//
//	PUT  /v1/purposes/{id}                          a new version -> P5           (consent-admin)
//	GET  /v1/purposes                               active purposes and their notices (anyone)
//	GET  /v1/purposes/{id}                          all versions                  (consent-admin)
//	GET  /v1/me                                     my identifiers, consents and requests (a person)
//	PUT  /v1/me/consents/{purpose} {given, version} give or withdraw              (a person)
//	POST /v1/me/requests {type, note, purposes}     a data-subject request        (a person)
//	GET  /v1/me/requests/{id}   GET /v1/me/requests/{id}/export
//	POST /v1/subjects {identifiers}                 find or register a person     (recorder app, dpo)
//	GET  /v1/subjects/{id}                                                        (dpo)
//	PUT  /v1/subjects/{id}/consents/{purpose} {given, version, evidence}          (recorder app, dpo)
//	POST /v1/subjects/{id}/requests {type, note, purposes}                        (recorder app, dpo)
//	POST /v1/check {purpose, subject | identifiers} may this person's data be processed? (any app)
//	GET  /v1/requests?status=open|all   GET /v1/requests/{id}                     (dpo)
//	POST /v1/requests/{id}/verify {verified, note, identifiers}                   (dpo)
//	POST /v1/requests/{id}/complete {note, withdraw, restrict}                    (dpo)
//	GET  /v1/requests/{id}/export                                                 (dpo)

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, c, msg string) {
	reply(w, code, map[string]any{"error": map[string]any{"code": c, "message": msg}})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		fail(w, http.StatusBadRequest, "bad_request", "body: "+err.Error())
		return false
	}
	return true
}

func callerApp(r *http.Request) string {
	a, _, _ := strings.Cut(heain.Caller(r.Context()), ".")
	return a
}

func in(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// role: a person with role, or an app in apps.
func (e *Engine) role(r *http.Request, role string, apps []string) (string, bool) {
	if u := heain.UserOf(r.Context()); u != nil {
		return u.ID, u.HasRole(role)
	}
	return heain.Caller(r.Context()), in(apps, callerApp(r))
}

func (e *Engine) admin(w http.ResponseWriter, r *http.Request) (string, bool) {
	who, ok := e.role(r, AdminRole, e.Cfg.AdminCallers)
	if !ok {
		fail(w, http.StatusForbidden, "forbidden", "needs the "+AdminRole+" role")
	}
	return who, ok
}

func (e *Engine) dpo(w http.ResponseWriter, r *http.Request) (string, bool) {
	who, ok := e.role(r, DPORole, e.Cfg.AdminCallers)
	if !ok {
		fail(w, http.StatusForbidden, "forbidden", "needs the "+DPORole+" role")
	}
	return who, ok
}

// recorder: a DPO, or an app allowed to act for people.
func (e *Engine) recorder(w http.ResponseWriter, r *http.Request) (who, channel string, ok bool) {
	if who, ok := e.role(r, DPORole, e.Cfg.AdminCallers); ok {
		return who, "dpo", true
	}
	if heain.UserOf(r.Context()) == nil && in(e.Cfg.RecorderCallers, callerApp(r)) {
		return heain.Caller(r.Context()), "app", true
	}
	fail(w, http.StatusForbidden, "forbidden", "needs the "+DPORole+" role, or an app allowed to record for people")
	return "", "", false
}

// Register adds the endpoints to the app's server.
func (e *Engine) Register(srv *heain.Server) error {
	for pat, h := range map[string]http.HandlerFunc{
		"PUT /v1/purposes/{id}":                    e.putPurpose,
		"GET /v1/purposes":                         e.listPurposes,
		"GET /v1/purposes/{id}":                    e.getPurpose,
		"GET /v1/me":                               e.me,
		"PUT /v1/me/consents/{purpose}":            e.meConsent,
		"POST /v1/me/requests":                     e.meRequest,
		"GET /v1/me/requests/{id}":                 e.meGetRequest,
		"GET /v1/me/requests/{id}/export":          e.meExport,
		"POST /v1/subjects":                        e.postSubject,
		"GET /v1/subjects/{id}":                    e.getSubject,
		"PUT /v1/subjects/{id}/consents/{purpose}": e.subjectConsent,
		"POST /v1/subjects/{id}/requests":          e.subjectRequestAPI,
		"POST /v1/check":                           e.check,
		"GET /v1/requests":                         e.listRequests,
		"GET /v1/requests/{id}":                    e.getRequest,
		"POST /v1/requests/{id}/verify":            e.verify,
		"POST /v1/requests/{id}/complete":          e.complete,
		"GET /v1/requests/{id}/export":             e.dpoExport,
	} {
		if err := srv.HandleFunc(pat, h); err != nil {
			return err
		}
	}
	return nil
}

// ---- purposes ----

func (e *Engine) putPurpose(w http.ResponseWriter, r *http.Request) {
	who, ok := e.admin(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !idRe.MatchString(id) {
		fail(w, http.StatusBadRequest, "bad_request", "a purpose id is [a-z0-9_.-], up to 63 characters")
		return
	}
	var q PurposeInput
	if !decode(w, r, &q) {
		return
	}
	if err := q.Validate(); err != nil {
		fail(w, http.StatusBadRequest, "invalid_purpose", err.Error())
		return
	}
	v, err := e.SubmitPurpose(r.Context(), id, q, who)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", err.Error())
		return
	}
	reply(w, http.StatusAccepted, map[string]any{"purpose": id, "version": v.N, "state": v.State, "action_id": v.ActionID, "sha256": v.SHA256})
}

// PublicPurpose is a purpose as a consent form shows it.
type PublicPurpose struct {
	ID             string   `json:"id"`
	Version        int      `json:"version"`
	Title          string   `json:"title"`
	Notice         string   `json:"notice"`
	LawfulBasis    string   `json:"lawful_basis"`
	DataCategories []string `json:"data_categories,omitempty"`
	Retention      string   `json:"retention,omitempty"`
}

func (e *Engine) active() []PublicPurpose {
	out := []PublicPurpose{}
	for _, p := range e.Store.Purposes() {
		if v, ok := p.ActiveVersion(); ok {
			out = append(out, PublicPurpose{p.ID, v.N, v.Title, v.Notice, v.LawfulBasis, v.DataCategories, v.Retention})
		}
	}
	return out
}

func (e *Engine) listPurposes(w http.ResponseWriter, r *http.Request) {
	reply(w, http.StatusOK, map[string]any{"purposes": e.active()})
}

func (e *Engine) getPurpose(w http.ResponseWriter, r *http.Request) {
	if _, ok := e.admin(w, r); !ok {
		return
	}
	p, err := e.Store.Purpose(r.PathValue("id"))
	if err != nil {
		fail(w, http.StatusNotFound, "not_found", "no such purpose")
		return
	}
	reply(w, http.StatusOK, p)
}

// ---- a person (through heain-gateway) ----

func (e *Engine) person(w http.ResponseWriter, r *http.Request) (*heain.User, bool) {
	u := heain.UserOf(r.Context())
	if u == nil {
		fail(w, http.StatusForbidden, "forbidden", "for people (through heain-gateway)")
	}
	return u, u != nil
}

// mine finds (or, with create, registers) the person's subject by their
// heain-gateway account.
func (e *Engine) mine(r *http.Request, u *heain.User, create bool) (store.Subject, bool, error) {
	ids := []heain.SubjectIdentifier{{Kind: heain.IdentGatewayUser, Value: u.ID}}
	if create {
		s, _, err := e.RegisterSubject(r.Context(), ids)
		return s, err == nil, err
	}
	id, err := e.Store.Find(ids)
	if err != nil || id == "" {
		return store.Subject{}, false, err
	}
	s, err := e.Store.Subject(r.Context(), id)
	return s, err == nil, err
}

// RequestView is a request as people see it.
type RequestView struct {
	ID      string            `json:"id"`
	Type    string            `json:"type"`
	Status  string            `json:"status"`
	Created any               `json:"created"`
	Due     any               `json:"due"`
	Closed  any               `json:"closed,omitempty"`
	Outcome string            `json:"outcome,omitempty"`
	Export  bool              `json:"export_available,omitempty"`
	Results []store.AppResult `json:"results,omitempty"`
}

func view(q store.Request) RequestView {
	v := RequestView{ID: q.ID, Type: q.Type, Status: q.Status, Created: q.Created, Due: q.Due, Outcome: q.Outcome, Export: q.Bundle != "", Results: q.Results}
	if !q.Closed.IsZero() {
		v.Closed = q.Closed
	}
	return v
}

func (e *Engine) requestsOf(r *http.Request, subject string) []RequestView {
	out := []RequestView{}
	for _, ref := range e.Store.RequestRefs() {
		if q, err := e.Store.Request(r.Context(), ref.ID); err == nil && q.Subject == subject {
			out = append(out, view(q))
		}
	}
	return out
}

func (e *Engine) me(w http.ResponseWriter, r *http.Request) {
	u, ok := e.person(w, r)
	if !ok {
		return
	}
	s, found, err := e.mine(r, u, false)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", err.Error())
		return
	}
	if !found {
		reply(w, http.StatusOK, map[string]any{"subject": nil, "consents": []any{}, "requests": []any{}, "purposes": e.active()})
		return
	}
	latest := []store.Consent{}
	for _, p := range e.Store.Purposes() {
		if c, ok := s.Latest(p.ID); ok {
			latest = append(latest, c)
		}
	}
	reply(w, http.StatusOK, map[string]any{"subject": s.ID, "identifiers": s.Identifiers, "restricted": s.Restricted, "consents": latest,
		"history": s.Consents, "requests": e.requestsOf(r, s.ID), "purposes": e.active()})
}

type consentBody struct {
	Given    *bool  `json:"given"`
	Version  int    `json:"version"`
	Evidence string `json:"evidence"`
}

func (e *Engine) recordAPI(w http.ResponseWriter, r *http.Request, subject, by, channel string, q consentBody) {
	if q.Given == nil {
		fail(w, http.StatusBadRequest, "bad_request", "given: true or false")
		return
	}
	if len(q.Evidence) > 200 {
		fail(w, http.StatusBadRequest, "bad_request", "evidence: a reference of at most 200 characters")
		return
	}
	c, err := e.Record(r.Context(), subject, r.PathValue("purpose"), q.Version, *q.Given, by, channel, q.Evidence)
	switch {
	case errors.Is(err, store.ErrNotFound):
		fail(w, http.StatusNotFound, "not_found", err.Error())
	case err != nil:
		fail(w, http.StatusConflict, "conflict", err.Error())
	default:
		reply(w, http.StatusOK, c)
	}
}

func (e *Engine) meConsent(w http.ResponseWriter, r *http.Request) {
	u, ok := e.person(w, r)
	if !ok {
		return
	}
	var q consentBody
	if !decode(w, r, &q) {
		return
	}
	if q.Evidence != "" {
		fail(w, http.StatusBadRequest, "bad_request", "evidence is for recorders")
		return
	}
	s, _, err := e.mine(r, u, true)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", err.Error())
		return
	}
	e.recordAPI(w, r, s.ID, u.ID, "self", q)
}

type requestBody struct {
	Type     string   `json:"type"`
	Note     string   `json:"note"`
	Purposes []string `json:"purposes"`
}

func (e *Engine) fileAPI(w http.ResponseWriter, r *http.Request, subject, by, channel string, q requestBody) {
	req, err := e.File(r.Context(), subject, q.Type, q.Note, q.Purposes, by, channel)
	switch {
	case errors.Is(err, store.ErrNotFound):
		fail(w, http.StatusNotFound, "not_found", "no such subject")
	case err != nil:
		fail(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		reply(w, http.StatusCreated, view(req))
	}
}

func (e *Engine) meRequest(w http.ResponseWriter, r *http.Request) {
	u, ok := e.person(w, r)
	if !ok {
		return
	}
	var q requestBody
	if !decode(w, r, &q) {
		return
	}
	s, _, err := e.mine(r, u, true)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", err.Error())
		return
	}
	e.fileAPI(w, r, s.ID, u.ID, "self", q)
}

// myRequest is a request of the calling person.
func (e *Engine) myRequest(w http.ResponseWriter, r *http.Request) (store.Request, bool) {
	u, ok := e.person(w, r)
	if !ok {
		return store.Request{}, false
	}
	s, found, _ := e.mine(r, u, false)
	q, err := e.Store.Request(r.Context(), r.PathValue("id"))
	if !found || err != nil || q.Subject != s.ID {
		fail(w, http.StatusNotFound, "not_found", "no such request of yours")
		return store.Request{}, false
	}
	return q, true
}

func (e *Engine) meGetRequest(w http.ResponseWriter, r *http.Request) {
	if q, ok := e.myRequest(w, r); ok {
		reply(w, http.StatusOK, view(q))
	}
}

func (e *Engine) export(w http.ResponseWriter, r *http.Request, q store.Request) {
	if q.Bundle == "" {
		fail(w, http.StatusNotFound, "not_found", "no export for this request (yet)")
		return
	}
	b, err := e.Store.Bundle(r.Context(), q.Bundle)
	if err != nil {
		fail(w, http.StatusGone, "gone", "the export has expired")
		return
	}
	e.audit(r.Context(), "consent.request", "export_read", map[string]any{"request": q.ID, "bundle": b.ID})
	// body: the exact bytes that were signed (sha256, then the app key)
	reply(w, http.StatusOK, map[string]any{"bundle": json.RawMessage(b.Body), "body": base64.StdEncoding.EncodeToString(b.Body), "sha256": b.SHA256,
		"signature": base64.StdEncoding.EncodeToString(b.Signature), "cert": base64.StdEncoding.EncodeToString(b.Cert), "expires": b.Expires})
}

func (e *Engine) meExport(w http.ResponseWriter, r *http.Request) {
	if q, ok := e.myRequest(w, r); ok {
		e.export(w, r, q)
	}
}

// ---- recorders and DPOs ----

func (e *Engine) postSubject(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := e.recorder(w, r); !ok {
		return
	}
	var q struct {
		Identifiers []heain.SubjectIdentifier `json:"identifiers"`
	}
	if !decode(w, r, &q) {
		return
	}
	s, created, err := e.RegisterSubject(r.Context(), q.Identifiers)
	switch {
	case errors.Is(err, store.ErrConflict):
		fail(w, http.StatusConflict, "conflict", err.Error())
	case err != nil:
		fail(w, http.StatusBadRequest, "bad_request", err.Error())
	default: // the same answer whether the person was new (idempotent)
		reply(w, http.StatusOK, map[string]any{"subject": s.ID, "created": created})
	}
}

func (e *Engine) getSubject(w http.ResponseWriter, r *http.Request) {
	if _, ok := e.dpo(w, r); !ok {
		return
	}
	s, err := e.Store.Subject(r.Context(), r.PathValue("id"))
	if err != nil {
		fail(w, http.StatusNotFound, "not_found", "no such subject")
		return
	}
	reply(w, http.StatusOK, map[string]any{"subject": s, "requests": e.requestsOf(r, s.ID)})
}

func (e *Engine) subjectConsent(w http.ResponseWriter, r *http.Request) {
	who, channel, ok := e.recorder(w, r)
	if !ok {
		return
	}
	var q consentBody
	if !decode(w, r, &q) {
		return
	}
	if channel == "app" && q.Evidence == "" {
		fail(w, http.StatusBadRequest, "bad_request", "evidence: a reference to how the person agreed (a form, a recording)")
		return
	}
	e.recordAPI(w, r, r.PathValue("id"), who, channel, q)
}

func (e *Engine) subjectRequestAPI(w http.ResponseWriter, r *http.Request) {
	who, channel, ok := e.recorder(w, r)
	if !ok {
		return
	}
	var q requestBody
	if !decode(w, r, &q) {
		return
	}
	e.fileAPI(w, r, r.PathValue("id"), who, channel, q)
}

func (e *Engine) check(w http.ResponseWriter, r *http.Request) {
	if heain.UserOf(r.Context()) != nil {
		fail(w, http.StatusForbidden, "forbidden", "the check is for apps; a person sees their own consents at /v1/me")
		return
	}
	var q struct {
		Purpose     string                    `json:"purpose"`
		Subject     string                    `json:"subject"`
		Identifiers []heain.SubjectIdentifier `json:"identifiers"`
	}
	if !decode(w, r, &q) {
		return
	}
	if q.Purpose == "" || (q.Subject == "") == (len(q.Identifiers) == 0) {
		fail(w, http.StatusBadRequest, "bad_request", "purpose, and either subject or identifiers")
		return
	}
	c, err := e.CheckConsent(r.Context(), q.Purpose, q.Subject, q.Identifiers)
	switch {
	case errors.Is(err, store.ErrNotFound):
		fail(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, store.ErrConflict):
		fail(w, http.StatusConflict, "conflict", err.Error())
	case err != nil:
		fail(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		reply(w, http.StatusOK, c)
	}
}

func (e *Engine) listRequests(w http.ResponseWriter, r *http.Request) {
	if _, ok := e.dpo(w, r); !ok {
		return
	}
	all := r.URL.Query().Get("status") == "all"
	type row struct {
		RequestView
		Subject string `json:"subject"`
	}
	out := []row{}
	for _, ref := range e.Store.RequestRefs() {
		if !all && Closed(ref.Status) {
			continue
		}
		if q, err := e.Store.Request(r.Context(), ref.ID); err == nil {
			out = append(out, row{view(q), q.Subject})
		}
	}
	reply(w, http.StatusOK, map[string]any{"requests": out})
}

func (e *Engine) getRequest(w http.ResponseWriter, r *http.Request) {
	if _, ok := e.dpo(w, r); !ok {
		return
	}
	q, err := e.Store.Request(r.Context(), r.PathValue("id"))
	if err != nil {
		fail(w, http.StatusNotFound, "not_found", "no such request")
		return
	}
	reply(w, http.StatusOK, q)
}

func (e *Engine) verify(w http.ResponseWriter, r *http.Request) {
	who, ok := e.dpo(w, r)
	if !ok {
		return
	}
	var q struct {
		Verified    *bool                     `json:"verified"`
		Note        string                    `json:"note"`
		Identifiers []heain.SubjectIdentifier `json:"identifiers"`
	}
	if !decode(w, r, &q) {
		return
	}
	if q.Verified == nil || len(q.Note) > 2000 {
		fail(w, http.StatusBadRequest, "bad_request", "verified: true or false; note: at most 2000 characters")
		return
	}
	req, err := e.Verify(r.Context(), r.PathValue("id"), *q.Verified, q.Note, who, q.Identifiers)
	e.answer(w, req, err)
}

func (e *Engine) answer(w http.ResponseWriter, req store.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		fail(w, http.StatusNotFound, "not_found", "no such request")
	case errors.Is(err, ErrState), errors.Is(err, store.ErrConflict):
		fail(w, http.StatusConflict, "conflict", err.Error())
	case err != nil:
		fail(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		reply(w, http.StatusOK, view(req))
	}
}

func (e *Engine) complete(w http.ResponseWriter, r *http.Request) {
	who, ok := e.dpo(w, r)
	if !ok {
		return
	}
	var q struct {
		Note     string   `json:"note"`
		Withdraw []string `json:"withdraw"`
		Restrict *bool    `json:"restrict"`
	}
	if !decode(w, r, &q) {
		return
	}
	if strings.TrimSpace(q.Note) == "" || len(q.Note) > 2000 {
		fail(w, http.StatusBadRequest, "bad_request", "note: what was done, 1 to 2000 characters")
		return
	}
	req, err := e.Complete(r.Context(), r.PathValue("id"), q.Note, who, q.Withdraw, q.Restrict)
	e.answer(w, req, err)
}

func (e *Engine) dpoExport(w http.ResponseWriter, r *http.Request) {
	if _, ok := e.dpo(w, r); !ok {
		return
	}
	q, err := e.Store.Request(r.Context(), r.PathValue("id"))
	if err != nil {
		fail(w, http.StatusNotFound, "not_found", "no such request")
		return
	}
	e.export(w, r, q)
}
