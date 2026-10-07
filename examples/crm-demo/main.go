// Command crm-demo is an example app for heain-consent: it holds customers
// and their invoices and implements subject.rights with heain-sdk. Invoices
// have a retention floor; they are held on erasure unless the request
// carries an approved RETENTION_OVERRIDE. TEST ONLY: data lives in memory.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/heainframework/heain-sdk/heain"
)

type invoice struct {
	ID        string    `json:"id"`
	Amount    float64   `json:"amount"`
	KeepUntil time.Time `json:"keep_until"`
}

type customer struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Email       string    `json:"email,omitempty"`
	Phone       string    `json:"phone,omitempty"`
	GatewayUser string    `json:"gateway_user,omitempty"`
	Invoices    []invoice `json:"invoices,omitempty"`
	// HeldFor is heain-consent's subject id while invoices are kept after the
	// contact details were erased: a later pass (an approved override, or the
	// retention ending) finds the record by it.
	HeldFor string `json:"held_for,omitempty"`
}

type crm struct {
	mu   sync.Mutex
	n    int
	byID map[string]*customer
}

func (c *crm) matches(r heain.SubjectRequest, x *customer) bool {
	return (x.Email != "" && r.Has(heain.IdentEmail, x.Email)) || (x.Phone != "" && r.Has(heain.IdentPhone, x.Phone)) ||
		(x.GatewayUser != "" && r.Has(heain.IdentGatewayUser, x.GatewayUser)) || r.Has("crm-demo:customer", x.ID) || (x.HeldFor != "" && x.HeldFor == r.Subject)
}

func (c *crm) export(_ context.Context, r heain.SubjectRequest) (heain.SubjectExport, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := heain.SubjectExport{}
	for _, x := range c.sorted() {
		if c.matches(r, x) {
			out.Items = append(out.Items, heain.SubjectItem{Kind: "customer", ID: x.ID, Data: *x})
		}
	}
	return out, nil
}

func (c *crm) erase(_ context.Context, r heain.SubjectRequest) (heain.SubjectErasure, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := heain.SubjectErasure{}
	now := time.Now()
	for _, x := range c.sorted() {
		if !c.matches(r, x) {
			continue
		}
		var keep []invoice
		for _, inv := range x.Invoices {
			if now.Before(inv.KeepUntil) && r.Override == "" {
				out.Held = append(out.Held, heain.SubjectItem{Kind: "invoice", ID: inv.ID, Reason: "retention_min", Until: inv.KeepUntil})
				keep = append(keep, inv)
				continue
			}
			out.Erased = append(out.Erased, heain.SubjectItem{Kind: "invoice", ID: inv.ID})
		}
		if len(keep) == 0 {
			out.Erased = append(out.Erased, heain.SubjectItem{Kind: "customer", ID: x.ID})
			if !r.DryRun {
				delete(c.byID, x.ID)
			}
			continue
		}
		// the customer stays as long as an invoice must: only what the invoices need
		out.Erased = append(out.Erased, heain.SubjectItem{Kind: "customer.contact", ID: x.ID})
		if !r.DryRun {
			x.Email, x.Phone, x.GatewayUser, x.Invoices, x.HeldFor = "", "", "", keep, r.Subject
		}
	}
	if r.Override != "" {
		log.Printf("crm-demo: request %s erased under RETENTION_OVERRIDE %s", r.Request, r.Override)
	}
	return out, nil
}

func (c *crm) sorted() []*customer {
	var out []*customer
	for _, x := range c.byID {
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	app, err := heain.StartFromEnv(ctx)
	if err != nil {
		log.Fatal(err)
	}
	if err := app.WaitActive(ctx); err != nil {
		log.Fatal(err)
	}
	c := &crm{byID: map[string]*customer{}}
	srv := app.NewServer()
	if err := srv.HandleSubjectRights(heain.SubjectRights{Export: c.export, Erase: c.erase}); err != nil {
		log.Fatal(err)
	}
	_ = srv.HandleFunc("POST /v1/customers", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Name, Email, Phone string
			GatewayUser        string `json:"gateway_user"`
			Invoices           []struct {
				Amount   float64 `json:"amount"`
				KeepDays int     `json:"keep_days"`
			} `json:"invoices"`
		}
		if json.NewDecoder(r.Body).Decode(&q) != nil || q.Name == "" {
			http.Error(w, `{"error":{"code":"bad_request","message":"name"}}`, http.StatusBadRequest)
			return
		}
		c.mu.Lock()
		c.n++
		x := &customer{ID: "c-" + app.Instance + "-" + itoa(c.n), Name: q.Name, Email: heain.NormalizeIdentifier(heain.IdentEmail, q.Email),
			Phone: heain.NormalizeIdentifier(heain.IdentPhone, q.Phone), GatewayUser: q.GatewayUser}
		for i, inv := range q.Invoices {
			x.Invoices = append(x.Invoices, invoice{ID: x.ID + "-inv" + itoa(i+1), Amount: inv.Amount, KeepUntil: time.Now().AddDate(0, 0, inv.KeepDays).UTC()})
		}
		c.byID[x.ID] = x
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(x)
	})
	_ = srv.HandleFunc("GET /v1/customers", func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"customers": c.sorted()})
	})
	l, err := net.Listen("tcp", heain.Listen(":19541"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("crm-demo: active on %s", l.Addr())
	if err := srv.Serve(ctx, l); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
	_ = app.Close(context.Background())
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
