# SPEC-0001 — llm-waf v0.1 Technical Specification

**Status:** Draft
**Date:** 2026-04-18
**Author:** Facundo Ibarzabal
**Applies to:** llm-waf v0.1.x
**Companion document:** [RFC-0001](./RFC.md)

This document specifies the public API, data contracts, detection primitives, PII recognizers, audit schema, and benchmark methodology that v0.1 of llm-waf must implement. It is not a design exploration — strategic decisions live in the RFC. This document is the implementation target.

---

## 1. Scope

v0.1 delivers:

- The core package (`llm-waf`) with deterministic detectors, LATAM PII recognizers, and the fluent schema builder.
- The Express adapter (`@llm-waf/express`) packaged in the same repository as a sub-directory publish target.
- A JSON-lines audit sink built in.
- A reproducible benchmark harness.
- Test fixtures and a CI matrix covering Node.js ≥ 20, Bun, Deno, Cloudflare Workers (Miniflare), and Vercel Edge (`@edge-runtime/vm`).

Out of scope for v0.1: MCP adapter, Hono / Next.js adapters, OpenTelemetry / Splunk / Datadog sinks, output validation, ONNX escalator, OpenAI Moderation adapter. These are scheduled for v0.2 – v1.0 per the RFC roadmap.

## 2. Public API surface

### 2.1 Entry points

The package exports a single namespace `waf` plus a small number of named helpers.

```ts
// llm-waf
export const waf: WafBuilder;
export type { WafSchema, WafValidationResult, AuditEvent, AuditSink, PiiLocale };
export { configureSink, resetSink };
```

### 2.2 WafBuilder

```ts
interface WafBuilder {
  string(): WafStringBuilder;
  prompt<TShape extends Record<string, WafSchema>>(shape: TShape): WafPromptSchema<TShape>;
  middleware<S extends WafSchema>(schema: S, options?: MiddlewareOptions): ExpressMiddleware;
}
```

- `waf.string()` returns a fluent string-schema builder (§ 3).
- `waf.prompt(shape)` composes multiple field schemas into a prompt-level schema with a uniform audit context.
- `waf.middleware(schema, options)` returns an Express request handler that validates `req.body` against the schema, emits audit events, and rejects with a configurable HTTP status on block decisions.

### 2.3 Validation result type

```ts
type WafValidationResult<T> =
  | { ok: true; value: T; events: AuditEvent[] }
  | { ok: false; errors: WafError[]; events: AuditEvent[] };
```

Validation always returns `events` (possibly empty) so callers can forward them to custom sinks or test assertions.

### 2.4 Standard Schema interop

Every `WafSchema` produced by the builder implements Standard Schema v1. Consumers (MCP v2 servers, OpenAI Agents SDK, any library that accepts Standard Schema) can pass a `WafSchema` wherever a Standard Schema is expected. The integration is one-way: llm-waf does not wrap arbitrary Standard Schemas in its builder in v0.1.

## 3. Fluent builder specification

### 3.1 WafStringBuilder

```ts
interface WafStringBuilder {
  // Structural
  minLength(n: number): this;
  maxLength(n: number): this;
  pattern(regex: RegExp): this;
  uuid(): this;
  email(): this;

  // Unicode handling
  normalize(form?: 'NFC' | 'NFKC'): this;        // default NFKC when .noInjection() is enabled
  stripControlChars(): this;                      // removes C0/C1 controls except tab/LF/CR
  stripZeroWidth(): this;                         // removes ZWSP, ZWNJ, ZWJ, WJ, BOM

  // Security detectors
  noInjection(options?: NoInjectionOptions): this;
  noSecrets(options?: NoSecretsOptions): this;
  noPII(locales: PiiLocale[], policy?: PiiPolicy): this;

  // Output
  build(): WafSchema<string>;
}
```

Method chaining accumulates transforms and detectors. Transforms run before detectors. Detection order within a single schema is insertion order; the first blocking failure short-circuits.

### 3.2 WafPromptSchema

```ts
interface WafPromptSchema<TShape> extends WafSchema<InferShape<TShape>> {
  validate(input: unknown): WafValidationResult<InferShape<TShape>>;
}
```

Field-level events carry the field name in their `target` property (§ 6.1). A single prompt validation can emit multiple events (one per field at minimum, plus one aggregate prompt-level event).

### 3.3 Policy composition rules

- `normalize()` and the `strip*` methods are always safe (they do not block; they transform).
- `noInjection()` implicitly enables `normalize('NFKC')` and `stripZeroWidth()` unless already configured.
- `noPII()` with `policy: 'redact'` mutates the value and emits a `flag` event; `policy: 'block'` rejects and emits a `block` event. Default policy is `redact`.
- `noSecrets()` always blocks on match.

## 4. Deterministic detectors

### 4.1 noInjection — signature set

The v0.1 signature set consists of normalized regex patterns organized by attack family. Each signature carries a `severity` (`low | medium | high`) and a `reference` to the attack in the public literature.

Baseline families in v0.1:

- **Instruction override** — "ignore previous instructions", "disregard above", "forget everything", "new instructions:", "system:" role spoofing. Severity: high. References: Perez & Ribeiro 2022; OWASP LLM01.
- **Role / persona breakout** — "you are now", "act as", "DAN mode", "developer mode", "jailbreak mode". Severity: medium.
- **System prompt extraction** — "repeat the above", "print your instructions", "what was your system prompt". Severity: high. References: OWASP LLM07.
- **Exfiltration via markdown** — `![...](http...)` patterns where the URL is dynamic. Severity: high. References: Johann Rehberger, embracethered.com.
- **Tool / function-call hijack** — patterns matching common tool-call syntaxes injected by the user. Severity: high.

The signature set is versioned independently of the package (`signatures/1.0.0`) and shipped as a JSON file consumable by `llm-waf` at load time. Signature updates can ship in patch releases without public API changes.

Out of scope for v0.1: language-model-generated paraphrases of the above (covered by the v0.5 optional ONNX escalator).

### 4.2 Unicode normalization

Default when `noInjection()` is active: `String.prototype.normalize('NFKC')` before signature matching. NFKC maps compatibility characters (e.g., full-width Latin letters, mathematical alphanumeric) to their canonical forms, closing homoglyph and encoding-trick vectors.

Override via `.normalize('NFC')` when the application expects to preserve compatibility characters (e.g., Arabic diacritic-sensitive content, East Asian typography). The override is a documented trade-off: weaker defense against homoglyph injection in exchange for input fidelity.

### 4.3 Zero-width and control character stripping

`stripZeroWidth()` removes characters in the Unicode general category `Cf` (Format) plus specific points commonly used in prompt smuggling:

| Codepoint | Name |
|---|---|
| U+200B | Zero-width space |
| U+200C | Zero-width non-joiner |
| U+200D | Zero-width joiner |
| U+2060 | Word joiner |
| U+FEFF | BOM / Zero-width no-break space |
| U+180E | Mongolian vowel separator |
| U+00AD | Soft hyphen |

`stripControlChars()` removes characters in the Unicode general category `Cc` (Control) except U+0009 (tab), U+000A (LF), and U+000D (CR).

### 4.4 Canary tokens

Canary tokens are unique opaque strings inserted into the system prompt by the application so that the validator can detect when the model has been coerced into revealing the system prompt. The library exposes:

```ts
waf.canary.generate(): string;
waf.canary.register(token: string, scope: 'request' | 'session' | 'global'): void;
waf.canary.check(output: string): CanaryDetection | null;
```

Token format: 16 bytes from `crypto.getRandomValues()` base64url-encoded, wrapped in a delimited pattern `⟦waf:{base64}⟧` chosen to be unlikely in legitimate text while remaining model-safe.

Scope semantics:

- `request` — token lives for a single `validate()` call. Registry is a `WeakRef` on the returned schema.
- `session` — token persists for a user-defined session identifier; registry is an LRU map, default 10 000 entries, configurable.
- `global` — token is long-lived; registry is an append-only set. v0.1 does not ship a persistent backing store; callers must persist across process restarts.

Canary leak detection is a post-response check: the application calls `waf.canary.check(modelOutput)` after receiving the LLM response. Detection emits an audit event with OWASP tag `LLM07` (System Prompt Leakage).

## 5. PII recognizers catalog

This section specifies the seven LATAM-first recognizers shipped in v0.1. Each recognizer consists of a pattern-matching stage (regex) and an optional checksum validation stage. Recognizers with checksums reduce false-positive rates materially compared to pattern-only matching.

Redaction format for all recognizers when policy is `redact`: `[REDACTED_{TYPE}]` where `{TYPE}` is the recognizer identifier (e.g., `[REDACTED_CPF]`).

### 5.1 DNI-AR (Argentina) — `dni-ar`

- **Format:** 7 or 8 decimal digits, optionally grouped by dots: `XX.XXX.XXX` or `XXXXXXXX`.
- **Regex:** `\b(\d{1,2}\.?\d{3}\.?\d{3})\b`
- **Checksum:** None. Argentine DNI has no published check digit. Pattern-only matching accepted.
- **Notes:** Matching is constrained to the 1 000 000 – 99 999 999 numeric range to reduce false positives on generic long numerics.
- **Source:** RENAPER (Registro Nacional de las Personas).

### 5.2 CPF-BR (Brazil) — `cpf-br`

- **Format:** 11 decimal digits, optionally masked as `XXX.XXX.XXX-XX`.
- **Regex:** `\b(\d{3}\.?\d{3}\.?\d{3}-?\d{2})\b`
- **Checksum:** Módulo 11 over the first nine digits with weights 10..2, then over the first ten digits with weights 11..2. Each check digit is `11 - (sum mod 11)`; if the result is 10 or 11, use 0. Reject numbers with all identical digits (e.g., `11111111111`) per Receita Federal rule.
- **Source:** Receita Federal do Brasil.

### 5.3 CNPJ-BR (Brazil) — `cnpj-br`

- **Format:** 14 decimal digits, optionally masked as `XX.XXX.XXX/XXXX-XX`.
- **Regex:** `\b(\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2})\b`
- **Checksum:** Módulo 11 with staggered weights `[5,4,3,2,9,8,7,6,5,4,3,2]` for the first check digit and `[6,5,4,3,2,9,8,7,6,5,4,3,2]` for the second. Same "all identical digits" rejection as CPF.
- **Source:** Receita Federal do Brasil.

### 5.4 CURP-MX (Mexico) — `curp-mx`

- **Format:** 18 characters, alphanumeric, structured as:
  `AAAA` (4 letters from names) + `YYMMDD` + `H|M` + `EE` (state) + `CCC` (consonants) + `D` (disambiguator digit or letter) + `V` (check digit, 0-9).
- **Regex:** `\b([A-Z][AEIOUX][A-Z]{2}\d{6}[HM][A-Z]{2}[B-DF-HJ-NP-TV-Z]{3}[0-9A-Z]\d)\b`
- **Checksum:** Weighted sum over first 17 characters (each character's position in `0123456789ABCDEFGHIJKLMNÑOPQRSTUVWXYZ`, weight descending from 18), check digit is `(10 - (sum mod 10)) mod 10`.
- **Source:** RENAPO (Registro Nacional de Población).

### 5.5 RFC-MX (Mexico) — `rfc-mx`

- **Format:** 12 characters for entities, 13 for individuals. Letters + YYMMDD + 3-character homoclave (alphanumeric, includes check digit).
- **Regex (individuals):** `\b([A-Z&Ñ]{4}\d{6}[A-Z0-9]{3})\b`
- **Regex (entities):** `\b([A-Z&Ñ]{3}\d{6}[A-Z0-9]{3})\b`
- **Checksum:** The final character is a check digit computed over the first 11 or 12 characters using a base-34 weighted sum. Full algorithm published by SAT (Servicio de Administración Tributaria). v0.1 validates the homoclave character-set; full checksum recomputation is deferred to v0.2 pending published reference implementation.

### 5.6 RUT-CL (Chile) — `rut-cl`

- **Format:** 7 or 8 digits followed by a hyphen and a check character (digit 0-9 or `K`). Optionally dotted: `XX.XXX.XXX-K`.
- **Regex:** `\b(\d{1,2}\.?\d{3}\.?\d{3}-?[0-9Kk])\b`
- **Checksum:** Módulo 11 with weights cycling `[2,3,4,5,6,7]` right-to-left over the numeric portion. `11 - (sum mod 11)` maps: 11 → 0, 10 → K, else digit.
- **Source:** Servicio de Impuestos Internos (SII).

### 5.7 Cédula-CO (Colombia) — `cedula-co`

- **Format:** 6 to 10 decimal digits (varies by era and document type). No standardized check digit across all eras.
- **Regex:** `\b(\d{6,10})\b`
- **Checksum:** None in v0.1. Pattern-only matching with range heuristics to reduce false positives (e.g., exclude values that match common phone number formats).
- **Notes:** Colombian NIT (tax ID) uses a separate checksum and is not covered by this recognizer. Scheduled as `nit-co` for v0.2.
- **Source:** Registraduría Nacional del Estado Civil.

### 5.8 International categories (best-effort)

v0.1 also ships recognizers for:

- Email (`email`) — per RFC 5322 simplified
- Credit card (`credit-card`) — Luhn-validated, 13 – 19 digits
- IBAN (`iban`) — MOD-97 per ISO 13616
- Generic international phone (`phone-intl`) — E.164 shape

These are convenience recognizers, not a Presidio replacement. Feature parity with Presidio is not a v0.1 goal.

## 6. Audit event schema

### 6.1 Event shape

```ts
interface AuditEvent {
  version: '1.0';                       // audit schema version; stable within 1.x
  timestamp: string;                    // RFC 3339 with millisecond precision
  decision: 'allow' | 'block' | 'flag';
  target: {
    schema: string;                     // user-supplied schema identifier or 'anonymous'
    field?: string;                     // field name for prompt-level schemas
    locator?: string;                   // dot-path for nested fields
  };
  detector: {
    name: string;                       // e.g., 'noInjection', 'noPII', 'stripZeroWidth'
    signature?: string;                 // signature family if applicable
    severity?: 'low' | 'medium' | 'high';
  };
  owaspLlm?: OwaspLlmCode[];            // see 6.2
  nistAiRmf?: NistSubcategory[];        // see 6.3
  redaction?: {
    type: string;                       // e.g., 'cpf-br'
    count: number;                      // matches redacted in this field
  };
  metadata: {
    runtime: 'node' | 'bun' | 'deno' | 'workerd' | 'edge-runtime' | 'unknown';
    libVersion: string;                 // llm-waf package version
    signatureVersion?: string;          // injection signature set version
  };
}
```

The schema is stable across minor versions. Additive fields are allowed; breaking changes require a major version bump of the audit schema (independent of the package SemVer).

### 6.2 OWASP LLM Top 10 2025 mapping

| Detector | OWASP Code(s) |
|---|---|
| `noInjection` — instruction override | `LLM01` |
| `noInjection` — system prompt extraction | `LLM01`, `LLM07` |
| `noInjection` — exfiltration via markdown | `LLM02`, `LLM06` |
| `noPII` | `LLM02` |
| `noSecrets` | `LLM02` |
| `canary.check` (leak detected) | `LLM07` |

`LLM03`–`LLM05`, `LLM08`–`LLM10` cover supply chain, data / model poisoning, improper output handling, vector-store weakness, and unbounded consumption — outside the v0.1 detector surface.

### 6.3 NIST AI RMF Generative AI Profile (AI 600-1) mapping

| Detector | NIST Subcategory |
|---|---|
| `noInjection`, `noSecrets` | `MEASURE 2.6` (Information Security), `MEASURE 2.7` (System Security) |
| `noPII` | `MEASURE 2.6`, `MANAGE 4.1` (Monitoring) |
| `canary.check` | `MEASURE 2.6`, `MANAGE 2.3` (Incident response) |

### 6.4 Sink interface

```ts
interface AuditSink {
  write(event: AuditEvent): void | Promise<void>;
  flush?(): Promise<void>;
}
```

- `write` is called synchronously from the hot path; sinks that do I/O must buffer and flush asynchronously to preserve the sub-10 ms budget.
- `flush` is called on process shutdown (callers hook this to `SIGTERM`, `beforeExit`, or framework shutdown events).

### 6.5 Default JSON-lines sink

A built-in sink writes one JSON document per line to a caller-supplied writable (`process.stderr` by default on Node.js; `console.error` fallback on edge runtimes without `process.stderr`). Line terminator is `\n` regardless of host OS.

## 7. Express adapter (`@llm-waf/express`)

### 7.1 Contract

```ts
import { waf } from 'llm-waf';
import express from 'express';

const app = express();
app.use(express.json());

const PromptSchema = waf.prompt({
  message: waf.string().maxLength(2000).noInjection().noPII(['es-AR']),
});

app.post(
  '/chat',
  waf.middleware(PromptSchema, {
    rejectStatus: 400,
    onBlock: (req, res, result) => {
      res.status(400).json({ error: 'validation_failed', events: result.events });
    },
  }),
  (req, res) => {
    // req.body is WafValidationResult<typeof PromptSchema>.value
    // Audit events already emitted.
  }
);
```

### 7.2 Request decoration

On `allow`, the middleware replaces `req.body` with the validated (and possibly redacted) value. The original unvalidated body is preserved at `req.wafRawBody` for audit-level reconstruction.

### 7.3 Rejection flow

Default behavior on `block`: respond `400 Bad Request` with a JSON body containing the list of `AuditEvent`s (minus the `metadata` section by default for brevity; togglable). The caller can override via `onBlock`.

## 8. Benchmark methodology

### 8.1 Goal

Verify the design principle "sub-10 ms P99 on deterministic checks" (RFC § 4.3) is upheld for every tagged release.

### 8.2 Reference hardware

Primary: GitHub Actions `ubuntu-latest` runner (Linux x86-64, 4 vCPU, current generation). Secondary: Apple M-series local validation. Both numbers published per release.

### 8.3 Input corpus

- 10 000 synthetic prompts, length distribution:
  - 30 % at 0 – 200 chars
  - 40 % at 200 – 800 chars
  - 25 % at 800 – 1 600 chars
  - 5 % at 1 600 – 2 000 chars
- 70 % benign, 30 % adversarial. Adversarial sourced from:
  - HackAPrompt subset (Schulhoff et al. 2023, EMNLP)
  - prompt-injection-defenses corpus (tldrsec/prompt-injection-defenses)
  - Internally generated LATAM-language variants (Spanish and Portuguese)

### 8.4 Measurement

- Harness: `mitata` (lowest overhead available as of 2026).
- Warm-up: 1 000 iterations, discarded.
- Measurement: 10 000 iterations per fixture.
- Metrics reported: mean, P50, P95, P99, P99.9, max.
- Wall-clock only; no CPU-time approximations.

### 8.5 Acceptance thresholds

For a release to tag:

- P99 ≤ 10 ms on the reference hardware across the full corpus.
- P99.9 ≤ 25 ms.
- Memory allocation per validation ≤ 64 KB (tracked via `--track-allocations`).
- No regression > 10 % vs the previous tagged release on any percentile.

A regression above threshold is a release blocker, not a warning.

### 8.6 CI integration

The benchmark runs on every PR against `main` and on every tag. Results are archived as release artifacts and published to a stable URL pattern: `https://github.com/facundoib/llm-waf/releases/download/v{version}/bench.json`.

## 9. Test strategy

### 9.1 Unit tests

- Every detector has positive (match) and negative (no-match) fixtures.
- Every PII recognizer includes valid, invalid, near-miss, and boundary-condition fixtures (issuing-authority documented samples cited in comments).
- Unicode normalization and stripping are tested against a curated set of smuggling vectors from `tldrsec/prompt-injection-defenses`.

### 9.2 Integration tests

- End-to-end Express adapter tests with `supertest`.
- JSON-lines sink output is asserted byte-for-byte.
- Canary token round-trip (generate → inject into mock system prompt → detect in mock model output).

### 9.3 Runtime matrix

CI exercises the core and the Express adapter on:

| Runtime | Source |
|---|---|
| Node.js 20 LTS | GitHub Actions `setup-node` |
| Node.js 22 | GitHub Actions `setup-node` |
| Bun latest | `oven-sh/setup-bun` |
| Deno latest | `denoland/setup-deno` |
| Cloudflare Workers | Miniflare 3 |
| Vercel Edge | `@edge-runtime/vm` |

The Express adapter tests are skipped on Deno and Workerd (no Express runtime there); a minimal Hono-like runtime test covers the non-Node targets for the core.

### 9.4 Fuzzing

Deferred to v0.2. Preliminary target: `fast-check` property tests on Unicode normalization and PII recognizer regex / checksum round-trips.

## 10. Error model

`WafError` covers every negative outcome.

```ts
interface WafError {
  code: WafErrorCode;
  field?: string;
  locator?: string;
  message: string;
  event: AuditEvent;
}

type WafErrorCode =
  | 'structural'        // length, pattern, type mismatch
  | 'injection'
  | 'pii-blocked'
  | 'secrets'
  | 'canary-leak'
  | 'invalid-input';    // malformed JSON, wrong top-level type
```

Error messages are stable (language-tagged strings). The library ships English strings by default; Spanish strings ship in v0.2 (LATAM doc track).

## 11. Versioning and stability

- **Package SemVer.** Major bumps on breaking public API changes; minor bumps on new features; patch bumps on bug fixes and signature set updates.
- **Audit schema versioning.** The audit schema carries its own `version` field. 1.x is stable; additive fields are minor, removals or type changes require 2.0 and a package major bump.
- **Signature set versioning.** Independently versioned (e.g., `signatures/1.2.0`). Signature additions that materially change false-positive rates are documented in release notes.
- **Deprecation policy.** Public API surfaces deprecated in a minor release are removed no sooner than the next major release with at least a 6-month overlap.

## 12. Open questions forwarded from RFC § 9

- **Canary scope default** — v0.1 defaults to `request` scope (safest, lowest memory). Session scope requires the caller to supply a session identifier and a bounded LRU; global scope requires the caller to supply a persistence layer.
- **Unicode normalization default** — v0.1 defaults to NFKC when `noInjection()` is active. Documented in README with the trade-off for non-Latin scripts.
- **RFC-MX checksum** — v0.1 validates format only; full homoclave checksum recomputation is tracked as a v0.2 milestone once an authoritative SAT reference implementation is reviewed.
- **MCP adapter interface** — deferred; blocked by MCP v2 beta. Will be specified in SPEC-0002.

## 13. References

- RFC-0001 (companion document in this repository).
- OWASP LLM Top 10 2025. https://genai.owasp.org
- NIST AI RMF Generative AI Profile (AI 600-1), July 2024.
- Standard Schema v1 specification. https://standardschema.dev
- HackAPrompt dataset. Schulhoff et al., EMNLP 2023.
- prompt-injection-defenses corpus. https://github.com/tldrsec/prompt-injection-defenses
- Receita Federal do Brasil — CPF / CNPJ format specifications.
- RENAPO — CURP format specification.
- SAT Mexico — RFC format specification.
- SII Chile — RUT format and Módulo 11 checksum.
- Registraduría Nacional del Estado Civil (Colombia) — cédula format.
