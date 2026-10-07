#!/usr/bin/env bash
# heain-consent live test 4.6d: consent and data-subject requests, end to end on a real heain-core node.
#   core G + heain-database + heain-gateway (people) + heain-notify (+ TEST ONLY sinks) + crm-demo x2 (subject.rights) + heain-consent.
#  - a consent-admin submits purposes through the gateway; they are offered (anonymously) only after P5;
#  - a person gives and withdraws consent through the gateway; a kiosk app registers another and records a paper form;
#    apps ask /v1/check before processing;
#  - an access request: the DPO is told, verifies the person and adds identifiers; both crm-demo instances answer;
#    the person downloads a signed export (openssl verifies heain-consent's key);
#  - an erasure: a dry run, P5 approves, crm-demo erases what it may and holds an invoice (retention), RETENTION_OVERRIDE
#    through P5, the invoice goes too; the person's record in heain-consent is shredded; another person is untouched;
#  - an erasure the Approver refuses changes nothing; nothing plaintext at rest or in the audit; the audit verifies.
# Needs ~/heain-core, ~/heain-sdk, ~/heain-database, ~/heain-gateway, ~/heain-notify. ~3 min.
# Run from ~/heain-consent:  bash scripts/live_4_6d.sh
set -uo pipefail
CS=$(cd "$(dirname "$0")/.." && pwd)
DBDIR=${HEAIN_DB_DIR:-$HOME/heain-database}; GWDIR=${HEAIN_GW_DIR:-$HOME/heain-gateway}; NTDIR=${HEAIN_NOTIFY_DIR:-$HOME/heain-notify}
cd ~/heain-core || { echo "needs ~/heain-core"; exit 1; }
H=./test_1_2_live.sh
T=$HOME/heain-core/.test-1.2
C=$T/certs; L=$T/logs; P=$T/pids; BIN=$T/node; W=$T/consent-4-6d
URL=https://127.0.0.1:18000
PUB=https://127.0.0.1:18443
NURL=https://127.0.0.1:19520
KURL=https://127.0.0.1:19540
EVURL=http://127.0.0.1:19521/v1/core-events
SINKS=$W/sinks.jsonl
API=$PUB/api/heain-consent
PASS=0; FAIL=0
ok()  { echo "  PASS: $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
as() { local who=$1; shift; curl -sk --noproxy '*' --cert "$C/$who.pem" --key "$C/$who.key" --cacert "$C/ca.pem" "$@"; }
code() { local who=$1; shift; as "$who" -o /dev/null -w "%{http_code}" "$@"; }
cl() { local who=$1; shift; curl -sk --noproxy '*' --cert "$W/$who.pem" --key "$W/$who.key" --cacert "$C/ca.pem" -H 'Content-Type: application/json' "$@"; }
j() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)" 2>/dev/null; }
mkcert() { [ -f "$C/$1.pem" ] && return; openssl genrsa -out "$C/$1.key" 2048 >/dev/null 2>&1
  openssl req -new -key "$C/$1.key" -subj "/CN=$1" -out "$C/$1.csr" >/dev/null 2>&1
  openssl x509 -req -in "$C/$1.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -out "$C/$1.pem" \
    -days 825 -sha256 -extfile <(printf "subjectAltName=DNS:%s" "$1") >/dev/null 2>&1; }
runapp() { local inst=$1 man=$2 port=$3 st=$4; shift 4; mkdir -p "$st"
  HEAIN_MANIFEST=$man HEAIN_INSTANCE=$inst HEAIN_CORE_URL=$URL HEAIN_CORE_ID=G HEAIN_CA=$C/ca.pem HEAIN_CHAIN=$W/prov.pem \
  HEAIN_STATE_DIR=$st HEAIN_ENROLL_TOKEN=$W/$inst.tok HEAIN_ENDPOINT_BASE=https://127.0.0.1:$port HEAIN_LISTEN=127.0.0.1:$port \
    nohup "$@" >> "$W/$inst.log" 2>&1 &
  echo $! > "$P/$inst.pid"; }
token() { as admin -X POST -H 'Content-Type: application/json' -d "{\"label\":\"$1\"}" $URL/provision/token > "$W/$2.tok"; }
pending() { as approver-1 $URL/v1/admin/policy/pending | j "' '.join(x['ID'] for x in d['actions'] if x['Type']=='$1')"; }
approve() { code approver-1 -X POST "$URL/v1/admin/policy/$1/approve"; }
setpol() { local id; id=$(as admin -X POST -d "{\"value\":$2}" $URL/v1/admin/config/policy/$1 | j "d['action_id']"); [ -n "$id" ] && [ "$(approve $id)" = 200 ]; }
audit() { as admin "$URL/v1/admin/audit?limit=2000&from=${1:-1}"; }
client() { as admin -X POST -H 'Content-Type: application/json' -d "{\"label\":\"$1\"}" $URL/provision/token > "$W/$1.json"
  python3 - "$W" "$1" <<'PY'
import json,sys; w,l=sys.argv[1],sys.argv[2]; d=json.load(open(f"{w}/{l}.json"))
open(f"{w}/{l}.boot.pem","w").write(d["bootstrap_cert_pem"]+open(w+"/prov.pem").read()); open(f"{w}/{l}.boot.key","w").write(d["bootstrap_key_pem"]); open(f"{w}/{l}.token","w").write(d["token"])
PY
  openssl genrsa -out "$W/$1.key" 2048 >/dev/null 2>&1; openssl req -new -key "$W/$1.key" -subj "/CN=$1" -out "$W/$1.csr" >/dev/null 2>&1
  python3 -c "import json;print(json.dumps({'token':open('$W/$1.token').read(),'csr_pem':open('$W/$1.csr').read()}))" > "$W/$1.req"
  curl -sk --noproxy '*' --cert "$W/$1.boot.pem" --key "$W/$1.boot.key" --cacert "$C/ca.pem" -X POST -H 'Content-Type: application/json' -d @"$W/$1.req" $URL/provision/csr \
    | python3 -c "import json,sys;open('$W/$1.pem','w').write(json.load(sys.stdin)['cert_pem']+open('$W/prov.pem').read())"; }
# people through heain-gateway (a cookie jar each, and its CSRF token)
pub() { local who=$1; shift; curl -sk --noproxy '*' -b "$W/$who.jar" -c "$W/$who.jar" -H 'Content-Type: application/json' "$@"; }
post() { local who=$1; shift; pub "$who" -X POST -H "X-CSRF-Token: $(cat "$W/$who.csrf" 2>/dev/null)" "$@"; }
put() { local who=$1; shift; pub "$who" -X PUT -H "X-CSRF-Token: $(cat "$W/$who.csrf" 2>/dev/null)" "$@"; }
login() { local out; out=$(pub "$1" -X POST -d "{\"username\":\"$2\",\"password\":\"$3\"${4:+,$4}}" $PUB/auth/login)
  echo "$out" | j "d.get('csrf_token','')" > "$W/$1.csrf"; echo "$out"; }
sinks() { python3 - "$SINKS" "$1" <<'PY' 2>/dev/null
import json,sys,os
rs=[json.loads(l) for l in open(sys.argv[1]) if l.strip()] if os.path.exists(sys.argv[1]) else []
print(sum(1 for r in rs if eval(sys.argv[2])))
PY
}
waitsink() { for k in $(seq 1 ${2:-30}); do [ "$(sinks "$1")" -ge "${3:-1}" ] 2>/dev/null && return 0; sleep 1; done; return 1; }
dreq() { pub dpo1 "$API/v1/requests/$1"; }
waitreq() { for k in $(seq 1 ${3:-40}); do [ "$(dreq "$1" | j "d['status']")" = "$2" ] && return 0; sleep 1; done; return 1; }
waitp5() { local id=""; for k in $(seq 1 30); do id=$(as approver-1 $URL/v1/admin/policy/pending | python3 -c "
import json,sys;d=json.load(sys.stdin);print(([x['ID'] for x in d['actions'] if x['Type']=='$1' and '$2' in json.dumps(x)]+[''])[0])" 2>/dev/null); [ -n "$id" ] && break; sleep 1; done; echo "$id"; }
crm() { cl ops.c1 "https://127.0.0.1:$1/v1/customers"; }

echo "== 0. core node G; build everything"
$H clean >/dev/null; $H build >/dev/null || { echo "core build failed"; exit 1; }; $H certs >/dev/null
mkdir -p "$L" "$P" "$T/data-G" "$W"; for c in admin approver-1; do mkcert $c; done
openssl genrsa -out "$W/prov.key" 2048 >/dev/null 2>&1
openssl req -new -key "$W/prov.key" -subj "/CN=heain-test-provisioning-ca" -out "$W/prov.csr" >/dev/null 2>&1
openssl x509 -req -in "$W/prov.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -out "$W/prov.pem" -days 30 -sha256 \
  -extfile <(printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign") >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/public.key" -out "$W/public.pem" -days 2 -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1
: > "$L/G.log"
nohup "$BIN" -node-id=G -tier=ZONE -raft-addr=127.0.0.1:19000 -data-dir="$T/data-G" -http-addr=127.0.0.1:18000 \
  -cert="$C/G.pem" -key="$C/G.key" -ca="$C/ca.pem" -admin-node-id=admin -approver-ids=approver-1 -bootstrap=true \
  -approval-store-path="$T/data-G/approvals.db" -provision-ca-cert="$W/prov.pem" -provision-ca-key="$W/prov.key" >> "$L/G.log" 2>&1 &
echo $! > "$P/G.pid"; sleep 6
B="GOFLAGS= GOWORK=${SDK_GOWORK:-}"
( cd "$CS" && eval "$B go build -o $W/heain-consent ./cmd/heain-consent" && eval "$B go build -o $W/crm-demo ./examples/crm-demo" ) \
  && ( cd "$GWDIR" && eval "$B go build -o $W/heain-gateway ./cmd/heain-gateway" ) \
  && ( cd "$NTDIR" && eval "$B go build -o $W/heain-notify ./cmd/heain-notify" && eval "$B go build -o $W/test-sinks ./tools/test-sinks" ) \
  && ok "heain-consent, crm-demo, heain-gateway, heain-notify and the test sinks build" || { bad "build"; exit 1; }
if [ -n "${HEAIN_DB_BIN:-}" ]; then cp "$HEAIN_DB_BIN" "$W/heain-database"; else ( cd "$DBDIR" && GOFLAGS= go build -o "$W/heain-database" ./cmd/heain-database ); fi
nohup "$W/test-sinks" -smtp 127.0.0.1:18525 -http 127.0.0.1:18526 -out "$SINKS" >> "$W/sinks.log" 2>&1 & echo $! > "$P/sinks.pid"
for k in $(seq 1 15); do [ "$(code admin -X POST -H 'Content-Type: application/json' -d '{"label":"probe.x"}' $URL/provision/token)" = 200 ] && break; sleep 1; done
client ops.c1

echo "== 1. the apps start and are admitted"
token heain-database.db1 db1; token heain-gateway.g1 g1; token heain-notify.n1 n1; token crm-demo.c1 c1; token crm-demo.c2 c2; token heain-consent.k1 k1
runapp db1 "$DBDIR/heain-app.yaml" 19460 "$W/state-db1" "$W/heain-database" -external-dialect sqlite
runapp g1 "$GWDIR/heain-app.yaml" 19500 "$W/state-g1" "$W/heain-gateway" -public-listen 127.0.0.1:18443 -public-cert "$W/public.pem" -public-key "$W/public.key" -bootstrap-admin root -routes-refresh 1s
runapp n1 "$NTDIR/heain-app.yaml" 19520 "$W/state-n1" "$W/heain-notify" -admin-callers ops -smtp-addr 127.0.0.1:18525 -smtp-from heain@example.test -smtp-mode plain
runapp c1 "$CS/examples/crm-demo/heain-app.yaml" 19541 "$W/state-c1" "$W/crm-demo"
runapp c2 "$CS/examples/crm-demo/heain-app.yaml" 19542 "$W/state-c2" "$W/crm-demo"
runapp k1 "$CS/heain-app.yaml" 19540 "$W/state-k1" "$W/heain-consent" -recorder-callers ops -poll 1s
for k in $(seq 1 60); do for a in $(pending app.register); do approve $a >/dev/null; done
  n=0; for x in "heain-gateway: active" "heain-notify: active" "crm-demo: active" "heain-consent: active"; do grep -qh "$x" "$W"/*.log && n=$((n+1)); done
  [ $n = 4 ] && [ "$(grep -l 'crm-demo: active' "$W"/c?.log | wc -l)" = 2 ] && break; sleep 1; done
[ $n = 4 ] && ok "heain-database, heain-gateway, heain-notify, crm-demo (c1, c2) and heain-consent admitted" || { bad "start: $n of 4 ($(tail -2 "$W/k1.log"))"; $H stop-all >/dev/null 2>&1; exit 1; }

echo "== 2. core policy: the gateway, its routes to heain-consent, events to heain-notify (all through P5)"
E='{"app":"heain-consent","method":'
setpol gateway.apps '["heain-gateway"]' && setpol gateway.exposures "[$E\"PUT\",\"path\":\"/v1/purposes/{id}\",\"roles\":[\"consent-admin\"]},$E\"GET\",\"path\":\"/v1/purposes\",\"auth\":\"anonymous\",\"rate_per_min\":60},
 $E\"GET\",\"path\":\"/v1/me\"},$E\"PUT\",\"path\":\"/v1/me/consents/{purpose}\"},$E\"POST\",\"path\":\"/v1/me/requests\"},$E\"GET\",\"path\":\"/v1/me/requests/{id}\"},$E\"GET\",\"path\":\"/v1/me/requests/{id}/export\"},
 $E\"GET\",\"path\":\"/v1/requests\",\"roles\":[\"dpo\"]},$E\"GET\",\"path\":\"/v1/requests/{id}\",\"roles\":[\"dpo\"]},$E\"POST\",\"path\":\"/v1/requests/{id}/verify\",\"roles\":[\"dpo\"]},
 $E\"POST\",\"path\":\"/v1/requests/{id}/complete\",\"roles\":[\"dpo\"]},$E\"GET\",\"path\":\"/v1/subjects/{id}\",\"roles\":[\"dpo\"]}]" \
  && setpol monitor.webhooks "[{\"url\":\"$EVURL\",\"events\":[\"*\"],\"results\":[\"WAITING_APPROVAL\",\"APPROVED_AND_RESUMED\",\"DENIED\"]}]" \
  && ok "gateway.apps, 12 heain-consent routes (the notices anonymous), and monitor.webhooks to heain-notify approved" || bad "policy"
read -r _ BOOT < "$W/state-g1/bootstrap-admin.txt"
login root root "$BOOT" '"new_password":"Gateway-Admin-Pass-1"' >/dev/null
mk() { post root -d "{\"id\":\"$1\",\"name\":\"$2\",\"roles\":$3,\"password\":\"$4\"}" $PUB/admin/users | j "d['account']['id']"; }
[ "$(mk cadmin 'Consent Admin' '["consent-admin"]' Consent-Admin-P1)" = cadmin ] && [ "$(mk dpo1 'Data Protection' '["dpo"]' Dpo-Officer-Pass1)" = dpo1 ] \
  && [ "$(mk somchai Somchai '["customer"]' Customer-Pass-001)" = somchai ] && [ "$(mk mali Mali '["customer"]' Customer-Pass-002)" = mali ] \
  && ok "people: cadmin (consent-admin), dpo1 (dpo), somchai and mali (customers)" || bad "users"
for x in "cadmin Consent-Admin-P1" "dpo1 Dpo-Officer-Pass1" "somchai Customer-Pass-001" "mali Customer-Pass-002"; do set -- $x; login "$1" "$1" "$2" >/dev/null; done
nput() { cl ops.c1 -o /dev/null -w '%{http_code}' -X PUT -d "$2" "$NURL$1"; }
[ "$(nput /v1/contacts/dpo1 '{"email":"dpo@example.test","gateway_user":"dpo1"}')$(nput /v1/contacts/somchai '{"email":"somchai@example.test","gateway_user":"somchai"}')$(nput /v1/contacts/ops '{"email":"ops@example.test"}')" = 200200200 ] \
  && [ "$(nput /v1/groups/dpo '{"members":["dpo1"]}')$(nput /v1/groups/ops-team '{"members":["ops"]}')" = 200200 ] && ok "notify contacts: dpo1, somchai, ops; groups dpo, ops-team" || bad "contacts"
for k in $(seq 1 20); do [ "$(curl -sk --noproxy '*' -o /dev/null -w '%{http_code}' $API/v1/purposes)" = 200 ] && break; sleep 1; done

echo "== 3. purposes: submitted by a consent-admin, offered only after P5"
MK='{"title":"Marketing","notice":"We send you offers by e-mail. You may withdraw at any time.","lawful_basis":"consent","data_categories":["contact"],"retention":"until withdrawn"}'
[ "$(put somchai -o /dev/null -w '%{http_code}' -d "$MK" $API/v1/purposes/marketing)" = 403 ] && ok "a customer cannot submit a purpose (the gateway refuses)" || bad "customer submit"
r=$(put cadmin -d "$MK" $API/v1/purposes/marketing); A1=$(echo "$r" | j "d['action_id']")
[ "$(echo "$r" | j "(d['version'],d['state'])")" = "(1, 'proposed')" ] && ok "cadmin submitted marketing v1: proposed, P5 $A1" || bad "submit: $r"
A2=$(put cadmin -d '{"title":"Billing","notice":"We keep invoices as the law requires.","lawful_basis":"contract"}' $API/v1/purposes/billing | j "d['action_id']")
[ "$(put cadmin -o /dev/null -w '%{http_code}' -d '{"title":"x","notice":"y","lawful_basis":"because"}' $API/v1/purposes/bad)" = 400 ] && ok "an unknown lawful basis is refused" || bad "basis"
[ "$(curl -sk --noproxy '*' $API/v1/purposes | j "len(d['purposes'])")" = 0 ] && ok "not active yet: nothing is offered" || bad "early"
approve $A1 >/dev/null; approve $A2 >/dev/null
for k in $(seq 1 15); do [ "$(curl -sk --noproxy '*' $API/v1/purposes | j "len(d['purposes'])")" = 2 ] && break; sleep 1; done
[ "$(curl -sk --noproxy '*' $API/v1/purposes | j "[(p['id'],p['version'],p['lawful_basis']) for p in d['purposes']]")" = "[('billing', 1, 'contract'), ('marketing', 1, 'consent')]" ] \
  && ok "approver-1 approved: anyone may read the notices (anonymous)" || bad "offered: $(curl -sk --noproxy '*' $API/v1/purposes)"

echo "== 4. consent: a person through the gateway, a kiosk app for another, apps ask"
chk() { cl ops.c1 -d "$1" $KURL/v1/check; }
[ "$(chk '{"purpose":"marketing","identifiers":[{"kind":"gateway_user","value":"somchai"}]}' | j "(d['allowed'],d['reason'])")" = "(False, 'no consent recorded')" ] && ok "check: somchai has not consented" || bad "check 0"
[ "$(put somchai -o /dev/null -w '%{http_code}' -d '{"given":true,"version":2}' $API/v1/me/consents/marketing)" = 409 ] && ok "consent to a version that is not the notice shown is refused" || bad "version"
[ "$(put somchai -d '{"given":true,"version":1}' $API/v1/me/consents/marketing | j "(d['given'],d['channel'],d['by'])")" = "(True, 'self', 'somchai')" ] && ok "somchai gave consent to marketing v1 through the gateway" || bad "give"
[ "$(chk '{"purpose":"marketing","identifiers":[{"kind":"gateway_user","value":"somchai"}]}' | j "(d['allowed'],d['consented_version'])")" = "(True, 1)" ] && ok "check: allowed" || bad "check 1"
put somchai -d '{"given":false}' $API/v1/me/consents/marketing >/dev/null
[ "$(chk '{"purpose":"marketing","identifiers":[{"kind":"gateway_user","value":"somchai"}]}' | j "(d['allowed'],d['reason'])")" = "(False, 'consent withdrawn')" ] && ok "somchai withdrew: check refuses" || bad "withdraw"
put somchai -d '{"given":true,"version":1}' $API/v1/me/consents/marketing >/dev/null
[ "$(chk '{"purpose":"billing","identifiers":[{"kind":"email","value":"nobody@example.test"}]}' | j "(d['allowed'],d['reason'])")" = "(True, 'lawful basis contract')" ] && ok "billing (contract) needs no consent" || bad "contract"
MS=$(cl ops.c1 -d '{"identifiers":[{"kind":"email","value":"Mali@Example.test"},{"kind":"phone","value":"+66 89 999 0000"}]}' $KURL/v1/subjects | j "d['subject']")
[ "$(cl ops.c1 -o /dev/null -w '%{http_code}' -X PUT -d '{"given":true,"version":1}' $KURL/v1/subjects/$MS/consents/marketing)" = 400 ] \
  && [ "$(cl ops.c1 -X PUT -d '{"given":true,"version":1,"evidence":"paper-form-17"}' $KURL/v1/subjects/$MS/consents/marketing | j "d['channel']")" = app ] \
  && [ "$(chk '{"purpose":"marketing","identifiers":[{"kind":"phone","value":"+66899990000"}]}' | j "d['allowed']")" = True ] \
  && ok "the kiosk app (ops) registered mali and recorded her paper form (evidence required); found by phone" || bad "recorder"
[ "$(cl ops.c1 -o /dev/null -w '%{http_code}' -d '{"identifiers":[{"kind":"email","value":"mali@example.test"},{"kind":"gateway_user","value":"somchai"}]}' $KURL/v1/subjects)" = 409 ] \
  && ok "identifiers of two different people are refused" || bad "conflict"
[ "$(pub somchai $API/v1/me | j "(len(d['consents']),d['consents'][0]['given'],len(d['history']))")" = "(1, True, 3)" ] && ok "somchai sees his consents and their history" || bad "me"

echo "== 5. crm-demo (two instances) holds personal data"
cust() { cl ops.c1 -o /dev/null -w '%{http_code}' -d "$2" "https://127.0.0.1:$1/v1/customers"; }
[ "$(cust 19541 '{"name":"Somchai Jaidee","email":"somchai@example.test","gateway_user":"somchai","invoices":[{"amount":1200,"keep_days":1825}]}')$(cust 19541 '{"name":"Mali Srisuk","email":"mali@example.test"}')$(cust 19542 '{"name":"S. Jaidee","phone":"+66 81-234-5678"}')" = 201201201 ] \
  && ok "c1: Somchai (with an invoice kept 5 years) and Mali; c2: Somchai by phone only" || bad "seed"

echo "== 6. an access request: the DPO verifies, every instance answers, a signed export"
r=$(post somchai -d '{"type":"access","note":"NOTE-SECRET what do you hold?"}' $API/v1/me/requests); R1=$(echo "$r" | j "d['id']")
[ "$(echo "$r" | j "d['status']")" = received ] && ok "somchai asked what is held ($R1), due in 30 days" || bad "file: $r"
waitsink "r['to']=='dpo@example.test' and '$R1' in r['body']" 20 && ok "the DPO group was told by email" || bad "dpo notice"
[ "$(pub mali -o /dev/null -w '%{http_code}' $API/v1/me/requests/$R1)" = 404 ] && [ "$(pub somchai -o /dev/null -w '%{http_code}' $API/v1/requests)" = 403 ] \
  && ok "mali cannot see it; a customer cannot open the DPO's list" || bad "visibility"
[ "$(pub dpo1 $API/v1/requests | j "[x['id'] for x in d['requests']]")" = "['$R1']" ] && ok "dpo1 sees it in the open requests" || bad "dpo list"
sleep 3; [ "$(dreq $R1 | j "d['status']")" = received ] && ok "nothing is collected before the DPO verifies" || bad "early collect"
[ "$(post dpo1 -d '{"verified":true,"note":"ID card checked at the counter","identifiers":[{"kind":"email","value":"somchai@example.test"},{"kind":"phone","value":"+66 81 234 5678"}]}' $API/v1/requests/$R1/verify | j "d['status']")" = verified ] \
  && ok "dpo1 verified somchai and added his e-mail and phone" || bad "verify"
waitreq $R1 completed 30 && ok "collected from every subject.rights instance: completed" || bad "collect: $(dreq $R1 | head -c 400)"
[ "$(pub somchai $API/v1/me/requests/$R1 | j "sorted((x['app'],x['instance'],x['items']) for x in d['results'])")" = "[('crm-demo', 'c1', 1), ('crm-demo', 'c2', 1)]" ] \
  && ok "c1 and c2 each answered (one record each)" || bad "results: $(pub somchai $API/v1/me/requests/$R1)"
pub somchai $API/v1/me/requests/$R1/export > "$W/export.json"
python3 - "$W" <<'PY'
import json,sys,base64; w=sys.argv[1]; d=json.load(open(w+"/export.json"))
open(w+"/export.body","wb").write(base64.b64decode(d["body"])); open(w+"/export.sig","wb").write(base64.b64decode(d["signature"])); open(w+"/export.der","wb").write(base64.b64decode(d["cert"]))
PY
openssl x509 -inform der -in "$W/export.der" -pubkey -noout > "$W/export.pub" 2>/dev/null
[ "$(openssl dgst -sha256 -verify "$W/export.pub" -signature "$W/export.sig" "$W/export.body" 2>&1)" = "Verified OK" ] && openssl x509 -inform der -in "$W/export.der" -noout -subject | grep -q heain-consent.k1 \
  && ok "somchai downloaded the export: signed by heain-consent.k1 (openssl verifies)" || bad "export signature"
[ "$(python3 -c "import json;d=json.load(open('$W/export.body'));print(sorted(i['data']['name'] for a in d['apps'] for i in a['items']), len(d['consents']), d['format'])")" = "['S. Jaidee', 'Somchai Jaidee'] 3 heain-consent-export/1" ] \
  && ok "it holds both crm records and his consent history" || bad "export body: $(head -c 300 "$W/export.body")"
waitsink "r['to']=='somchai@example.test' and '$R1' in r['body']" 15 && ok "somchai was told it is ready" || bad "ready notice"

echo "== 7. an erasure: dry run, P5, what retention holds, RETENTION_OVERRIDE"
R2=$(post somchai -d '{"type":"erasure"}' $API/v1/me/requests | j "d['id']")
post dpo1 -d '{"verified":true,"note":"same person as request 1"}' $API/v1/requests/$R2/verify >/dev/null
waitreq $R2 awaiting_approval 30 && ok "a dry run in every instance, then P5 (consent.erasure)" || bad "plan: $(dreq $R2 | j "d['status']")"
[ "$(dreq $R2 | j "sorted((x['instance'],len(x['erased']),[h['reason'] for h in x.get('held') or []]) for x in d['plan'])")" = "[('c1', 1, ['retention_min']), ('c2', 1, [])]" ] \
  && [ "$(crm 19541 | j "len(d['customers'])")" = 2 ] && ok "the plan: c1 erases the contact and holds the invoice (retention_min), c2 erases one; nothing changed yet" || bad "plan: $(dreq $R2 | j "d['plan']")"
PA=$(waitp5 consent.erasure "$R2")
waitsink "r['to']=='ops@example.test' and '$PA' in r['body']" 20 && ok "ops-team was told an erasure waits for an Approver ($PA)" || bad "p5 notice"
[ -n "$PA" ] && [ "$(approve $PA)" = 200 ] && ok "approver-1 approved the erasure" || bad "approve erasure"
waitreq $R2 awaiting_override 30 && ok "erased; what is held needs RETENTION_OVERRIDE" || bad "erasing: $(dreq $R2 | j "d['status']")"
[ "$(crm 19541 | j "sorted((c['name'],c.get('email',''),len(c.get('invoices') or [])) for c in d['customers'])")" = "[('Mali Srisuk', 'mali@example.test', 0), ('Somchai Jaidee', '', 1)]" ] \
  && [ "$(crm 19542 | j "len(d['customers'] or [])")" = 0 ] && ok "c1 keeps only the invoice (contact gone), c2's record is gone, Mali untouched" || bad "after pass 1: $(crm 19541) $(crm 19542)"
PO=$(waitp5 consent.erasure.override "$R2")
[ "$(as approver-1 $URL/v1/admin/policy/pending | j "[x['Category'] for x in d['actions'] if x['ID']=='$PO'][0]")" = RETENTION_OVERRIDE ] && [ "$(approve $PO)" = 200 ] \
  && ok "the override is a RETENTION_OVERRIDE; approver-1 approved it" || bad "override"
waitreq $R2 completed 30 && ok "the invoice went too: completed" || bad "override pass: $(dreq $R2 | j "d['status'],d['outcome']")"
[ "$(crm 19541 | j "[c['name'] for c in d['customers']]")" = "['Mali Srisuk']" ] && grep -q "erased under RETENTION_OVERRIDE $PO" "$W/c1.log" && ok "crm-demo c1: only Mali is left (it logged the override id)" || bad "c1: $(crm 19541)"
[ "$(dreq $R2 | j "d['outcome']")" = "4 item(s) erased in 2 app instance(s); the person's record here was shredded" ] && ok "the outcome: 4 items (c1: contact, then invoice and record; c2: record); somchai's record in heain-consent shredded" || bad "outcome: $(dreq $R2 | j "d['outcome']")"
[ "$(chk '{"purpose":"marketing","identifiers":[{"kind":"email","value":"somchai@example.test"}]}' | j "(d['allowed'],d['reason'])")" = "(False, 'no consent recorded')" ] \
  && [ "$(pub somchai $API/v1/me | j "d['subject']")" = None ] && ok "no identifier leads to him any more" || bad "after shred"
waitsink "r['to']=='somchai@example.test' and '$R2' in r['body']" 15 && ok "somchai was told" || bad "erasure notice"

echo "== 8. an erasure the Approver refuses changes nothing"
R3=$(cl ops.c1 -d '{"type":"erasure","note":"by phone call"}' $KURL/v1/subjects/$MS/requests | j "d['id']")
post dpo1 -d '{"verified":true,"note":"called back"}' $API/v1/requests/$R3/verify >/dev/null
waitreq $R3 awaiting_approval 30; PB=$(waitp5 consent.erasure "$R3")
[ "$(code approver-1 -X POST -d '{"reason":"open dispute"}' $URL/v1/admin/policy/$PB/reject)" = 200 ] && waitreq $R3 refused 20 \
  && [ "$(crm 19541 | j "[c['name'] for c in d['customers']]")" = "['Mali Srisuk']" ] && [ "$(chk '{"purpose":"marketing","identifiers":[{"kind":"email","value":"mali@example.test"}]}' | j "d['allowed']")" = True ] \
  && ok "mali's erasure (filed by the kiosk app): the Approver rejected it, her data and consent are untouched" || bad "refused: $(dreq $R3 | j "d['status']")"

echo "== 9. at rest; the audit"
s=$(python3 -c "import sys;b=open(sys.argv[1],'rb').read();print(sum(b.count(x.encode()) for x in sys.argv[2:]))" "$W/state-k1/consent.db" somchai@example.test mali@example.test 66899990000 NOTE-SECRET "ID card" paper-form-17 Jaidee)
[ "$s" = 0 ] && ok "consent.db holds no identifier, note or name in plaintext" || bad "plaintext: $s"
n=$(audit | j "sum(1 for x in d['records'] if x['event']['Action']=='app.event' and x['event']['Detail']['capability']=='subject.rights' and x['event']['Actor'].startswith('crm-demo.') and x['event']['Detail']['app_actor'].startswith('heain-consent.'))")
m=$(audit | j "sorted(set(x['event']['Result'] for x in d['records'] if x['event']['Action']=='app.event' and x['event']['Detail']['capability']=='consent.request'))")
[ "${n:-0}" -ge 8 ] && echo "$m" | grep -q "'completed'" && echo "$m" | grep -q "'awaiting_override'" && echo "$m" | grep -q "'refused'" && echo "$m" | grep -q "'verified'" \
  && ok "core's audit: crm-demo's subject.rights calls by heain-consent ($n) and every request step" || bad "audit: $n $m"
g=$(audit | j "sum(1 for x in d['records'] if x['event']['Action']=='app.event' and x['event']['Detail']['capability']=='consent.record' and (x['event']['Detail'].get('detail') or {}).get('user')=='somchai')")
[ "${g:-0}" -ge 3 ] && ok "somchai's consent changes are audited with his signed assertion ($g)" || bad "consent audit: $g"
audit | grep -q "somchai@example.test\|NOTE-SECRET\|Jaidee\|66899990000" && bad "personal data in the audit" || ok "no personal data in the audit chain"
[ "$(as admin $URL/v1/admin/audit/verify | j "d['ok']")" = True ] && ok "audit chain verifies" || bad "verify"

echo "== cleanup"
kill "$(cat "$P/sinks.pid")" 2>/dev/null
$H stop-all >/dev/null 2>&1
for f in db1 g1 n1 c1 c2 k1; do [ -f "$P/$f.pid" ] && kill "$(cat "$P/$f.pid")" 2>/dev/null; done
echo
echo "RESULT: $PASS passed, $FAIL failed"
echo "(logs: $W)"
