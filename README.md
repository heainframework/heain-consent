# heain-consent

Consent records and data-subject requests for a heain deployment, under PDPA (and GDPR alike) (Step 4.6d, 2026-10-07). It covers:

- the purposes of processing, each with its notice and lawful basis, versioned and activated through P5;
- people's consent: given and withdrawn by the person through heain-gateway, or recorded for them by an app (a kiosk, a CRM) with evidence;
- a check apps call before they process someone's data for a purpose;
- data-subject requests: access, portability, erasure, rectification, restriction and objection. A DPO verifies each one. Access and erasure are carried out in **every app that holds personal data**, from one request.

Built on [heain-sdk](https://github.com/heainframework/heain-sdk) v1 (it needs the Step 4.6d `subject.rights` helper). It needs heain-core with Step 4.6a (public endpoints and `gateway.exposures`). People reach it through [heain-gateway](https://github.com/heainframework/heain-gateway) and are told through [heain-notify](https://github.com/heainframework/heain-notify). It passes the heain conformance suite. Run it however you like: a plain process, a service unit, or a container (Docker is not required).

## Author decisions (2026-10-07)

1. **Reaching every app: a standard capability.** An app that holds personal data declares the shared capability `subject.rights` (heain-sdk `HandleSubjectRights`): export, and erase (with a dry run). heain-consent finds every live instance through core's discover and calls each one. No core change was needed.
2. **Identifying a person: a register of identifiers.** One data subject has several identifiers: `gateway_user`, `email`, `phone`, or app-specific ones such as `heain-access:subject`. heain-consent sends all of them; each app matches the ones it knows.
3. **Consent: purposes through P5; apps ask.** Purposes and notices are versioned, and a version becomes active through P5. Apps call `/v1/check`.
4. **Requests: the DPO verifies; erasure goes through P5.** What retention or a legal hold keeps goes through `RETENTION_OVERRIDE`. The PDPA deadline (30 days) is followed, with reminders through heain-notify.

## Purposes and consent

```json
PUT /v1/purposes/marketing
{"title": "Marketing", "notice": "We send you offers by e-mail. You may withdraw at any time.",
 "lawful_basis": "consent", "data_categories": ["contact"], "retention": "until withdrawn", "requires_reconsent": false}
```

- **Lawful basis:**
  - `consent`, where the person must agree;
  - `contract`, `legal_obligation`, `vital_interest`, `public_task` or `legitimate_interest`, where the check allows processing without consent.
- **A new version:**
  - It waits for P5 (`consent.purpose.activate`, `KNOWLEDGE_UPDATE`); the old one stays in force until then.
  - Consent is given to the active version, the notice the person was shown.
  - A version with `requires_reconsent: true` makes earlier consents stop counting.

`POST /v1/check {purpose, subject | identifiers}` answers:

```json
{"purpose": "marketing", "version": 2, "lawful_basis": "consent", "allowed": false, "consented_version": 1,
 "reason": "consent to version 1 no longer counts: version 2 needs it again"}
```

The `reason` field takes these values:

- `no consent recorded`
- `consent withdrawn`
- `restricted` (after a restriction request, nothing may be processed)
- `consent given`
- `lawful basis <basis>`

## Data-subject requests

| Type | After the DPO verifies |
|---|---|
| `access`, `portability` | Every `subject.rights` instance exports what it holds for the person. heain-consent adds the identifiers and consent history it holds, signs the bundle (SHA-256, then its app key), and keeps it sealed under its own key until `-export-ttl` (30 days). The key is then destroyed. |
| `erasure` | 1. A dry run in every instance.<br>2. P5 `consent.erasure`, with only counts and reasons, no personal data.<br>3. Each instance erases what it may and reports what it holds (`retention_min`, `legal_hold`, ...).<br>4. If anything is held, P5 `consent.erasure.override` (`RETENTION_OVERRIDE`). If approved, a second pass erases it too.<br>5. When nothing is held anywhere, the person's record in heain-consent is shredded (crypto-shred, and the identifier index is removed). Otherwise their consents are withdrawn and the record stays for what is held. |
| `rectification`, `restriction`, `objection` | The DPO carries it out and completes it. `withdraw: [purposes]` ends consent (objection); `restrict: true` makes every check answer `restricted`. |

Statuses: `received` → `verified` → `collecting` / `planning` → `awaiting_approval` → `erasing` → `awaiting_override` → `erasing_override` → `completed` / `completed_with_holds`; or `rejected` (the DPO could not verify), or `refused` (the Approver denied).

Each request is due 30 days after it arrives (`-due-days`). The `-dpo-group` (heain-notify) is told:

- when it arrives;
- `-remind-before` the deadline (7 days);
- when it is overdue (critical).

The person is told through their heain-gateway account when it closes. Messages carry only the request id.

## The `subject.rights` contract (for app developers)

```yaml
capabilities:
  - {name: subject.rights, version: 1, formal: true, execution: direct, ai: {used: false}}
endpoints:
  - {method: POST, path: /v1/subject-rights/export, capability: subject.rights, formal: true}
  - {method: POST, path: /v1/subject-rights/erase, capability: subject.rights, formal: true}
```

```go
srv.HandleSubjectRights(heain.SubjectRights{Export: exportFn, Erase: eraseFn})
// r.Has(heain.IdentEmail, x.Email), r.Values(heain.IdentPhone), r.DryRun, r.Override, r.Subject
```

- **Callers:** only heain-consent may call (configurable); heain-sdk refuses other apps.
- **Erase:**
  - Answer `{erased: [...], held: [{kind, id, reason, until}]}`, and change nothing on a dry run.
  - An erase answer never carries data.
  - When `override` names an approved `RETENTION_OVERRIDE`, erase what you held.
- **Something you keep after erasing its identifiers:** remember `r.Subject` with it, so the override pass still finds it.

`examples/crm-demo` shows all of this. Its customers have invoices with a retention floor.

## The API

All person and DPO endpoints are declared `public`, so an operator may expose them through heain-gateway (`gateway.exposures`, P5). `GET /v1/purposes` can be exposed anonymously for consent forms.

| Endpoint | Who |
|---|---|
| `PUT /v1/purposes/{id}`, `GET /v1/purposes/{id}` | `consent-admin` role, or an app in `-admin-callers` |
| `GET /v1/purposes` | anyone: the active purposes and their notices |
| `GET /v1/me`, `PUT /v1/me/consents/{purpose}`, `POST /v1/me/requests`, `GET /v1/me/requests/{id}[/export]` | a person (heain-gateway); found or registered by their `gateway_user` |
| `POST /v1/subjects` (find or register by identifiers), `PUT /v1/subjects/{id}/consents/{purpose}` (with `evidence` for an app), `POST /v1/subjects/{id}/requests` | `dpo` role, or an app in `-recorder-callers` |
| `GET /v1/subjects/{id}`, `GET /v1/requests[?status=all]`, `GET /v1/requests/{id}`, `POST /v1/requests/{id}/verify {verified, note, identifiers}`, `POST /v1/requests/{id}/complete {note, withdraw, restrict}`, `GET /v1/requests/{id}/export` | `dpo` role, or an app in `-admin-callers` |
| `POST /v1/check` | apps (not people) |

Every request is audited in core by heain-sdk, with the person's signed assertion. Consent given and withdrawn, and every request step, are audited too. Only ids go into the audit, never identifiers or data.

## At rest

The store is BoltDB, and everything in it is sealed under data keys from heain-core's KMS:

- each person (identifiers, consent history, restriction) under their own key;
- each request under its own key;
- each export bundle under its own key;
- purposes under the inside key.

Identifiers are indexed by HMAC only.

## Setting it up

```sh
go build -o heain-consent ./cmd/heain-consent
./heain-consent -recorder-callers kiosk -dpo-group dpo     # listens on :19540 (HEAIN_LISTEN)
```

Flags:

- `-admin-callers`;
- `-recorder-callers`;
- `-notify-app` (default `heain-notify`);
- `-dpo-group` (`dpo`);
- `-due-days` (30);
- `-remind-before` (7 days);
- `-export-ttl` (30 days);
- `-poll` (3 s).

The usual heain-sdk environment applies. Then:

1. Expose the routes through `gateway.exposures` (P5).
2. Give the DPO the `dpo` role and the purpose owner `consent-admin`.
3. In heain-notify, create the `dpo` group and contacts with `gateway_user`.

## Tests

```sh
go test ./...
bash scripts/live_4_6d.sh     # needs ~/heain-core, ~/heain-sdk, ~/heain-database, ~/heain-gateway, ~/heain-notify; ~3 min
```

The live test runs a real core node with heain-database, heain-gateway, heain-notify (with TEST ONLY sinks) and two crm-demo instances. It covers:

- purposes through P5, offered anonymously;
- consent given and withdrawn by a person, and recorded by a kiosk app with evidence;
- the check;
- an access request across both instances, with an export whose signature openssl verifies;
- an erasure with a held invoice, then a `RETENTION_OVERRIDE`, after which the person's record is shredded;
- an erasure the Approver refuses;
- nothing plaintext at rest or in the audit;
- the audit chain.
