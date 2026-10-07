// Command heain-consent keeps consent records and carries out data-subject
// requests (Step 4.6d). It is configured through the heain-sdk HEAIN_*
// variables (heain.StartFromEnv) plus the flags below, and runs however the
// operator likes: a plain process, a service unit, or a container.
package main

import (
	"context"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/heainframework/heain-consent/internal/consent"
	"github.com/heainframework/heain-consent/internal/store"
	"github.com/heainframework/heain-sdk/heain"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func list(s string) []string {
	var out []string
	for _, c := range strings.Split(s, ",") {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	return out
}

// platform adapts heain-sdk's App to consent.Platform.
type platform struct {
	*heain.App
	der []byte
}

func (p platform) CertDER() []byte { return p.der }

func main() {
	adminCallers := flag.String("admin-callers", os.Getenv("HEAIN_CONSENT_ADMIN_CALLERS"), "comma-separated app ids that may act as consent-admin and DPO without a person (people need those roles through heain-gateway)")
	recorders := flag.String("recorder-callers", os.Getenv("HEAIN_CONSENT_RECORDER_CALLERS"), "comma-separated app ids that may register people and record their consent and requests (a kiosk, a CRM)")
	notifyApp := flag.String("notify-app", "heain-notify", "the app that sends messages")
	dpoGroup := flag.String("dpo-group", "dpo", "the heain-notify group told about requests and deadlines")
	dueDays := flag.Int("due-days", 30, "days to answer a request (PDPA: 30)")
	remind := flag.Duration("remind-before", 7*24*time.Hour, "remind the DPO group this long before a request is due")
	bundleTTL := flag.Duration("export-ttl", 30*24*time.Hour, "how long an export stays available before its key is destroyed")
	poll := flag.Duration("poll", 3*time.Second, "how often P5 decisions are checked")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	state := env("HEAIN_STATE_DIR", "/state")
	app, err := heain.StartFromEnv(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "REFUSED: %v\n", err)
		os.Exit(2)
	}
	log.Printf("heain-consent: registered (%s), waiting for admission", app.Status())
	if err := app.WaitActive(ctx); err != nil {
		log.Fatal(err)
	}
	inside, err := app.DataKey(ctx, "inside")
	if err != nil {
		log.Fatalf("heain-consent: data key from core: %v", err)
	}
	st, err := store.Open(filepath.Join(state, "consent.db"), inside, store.Keys{Sealer: app.Sealer, Destroy: app.DestroyDataKey})
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()
	blk, _ := pem.Decode(app.CertificatePEM())
	eng := consent.New(&consent.Engine{Store: st, Plat: platform{app, blk.Bytes}, Logf: log.Printf,
		Cfg: consent.Config{Self: app.Manifest.App.ID, AdminCallers: list(*adminCallers), RecorderCallers: list(*recorders), NotifyApp: *notifyApp,
			DPOGroup: *dpoGroup, Due: time.Duration(*dueDays) * 24 * time.Hour, RemindBefore: *remind, BundleTTL: *bundleTTL, PollEvery: *poll}})
	go eng.Run(ctx)
	srv := app.NewServer()
	if err := eng.Register(srv); err != nil {
		log.Fatal(err)
	}
	l, err := net.Listen("tcp", heain.Listen(":19540"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("heain-consent: active on %s", l.Addr())
	if err := srv.Serve(ctx, l); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
	_ = app.Close(context.Background())
	log.Printf("heain-consent: deregistered")
}
