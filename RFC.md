# RFC-0001 — llm-waf: Architecture and Scope for v0.1

**Status:** Draft
**Date:** 2026-04-18
**Author:** Facundo Ibarzabal
**Target implementation window:** May 2026 – April 2027

## 1. Summary

llm-waf is a pure-TypeScript Web Application Firewall for LLM inputs, targeting Node.js and edge runtimes (Cloudflare Workers, Vercel Edge, Bun, Deno). It addresses a verified gap in the open-source landscape: no current library provides schema-composable input validation for LLM applications with (a) zero Python or machine-learning dependencies on the hot path, (b) a sub-5 MB install footprint compatible with serverless cold-starts, (c) first-class LATAM PII recognizers, and (d) audit output mapped to OWASP LLM Top 10 2025 and NIST AI RMF.

This RFC locks the architectural decisions for v0.1 and the roadmap through v1.0. It is the product of a comparative review of 12+ incumbent solutions (Guardrails AI, NVIDIA NeMo, LLM Guard, Microsoft Presidio, Rebuff, Arcjet, `@openai/guardrails`, Lakera Guard, Cloudflare Firewall for AI, AWS Bedrock Guardrails, Azure AI Content Safety, Google Model Armor), academic prompt-injection defense literature (Greshake et al. 2023; Perez & Ribeiro 2022; Hackett et al. 2025; StruQ; SmoothLLM), and a regulatory survey (EU AI Act Art. 15; Brazil PL 2338/2023; Chile Boletín 16821-19).

## 2. Problem

Modern TypeScript backends deploying LLM features face three structural problems that current OSS tooling does not solve.

### 2.1 Runtime impedance

The dominant OSS input-validation tools for LLMs (Guardrails AI, NeMo Guardrails, LLM Guard, Presidio) are Python-first. Node.js integration paths rely on Python subprocess bridges (`@guardrails-ai/core`), HTTP microservices (NeMo Guardrails Server), or Docker sidecars (Presidio). None of these are compatible with V8-isolate edge runtimes (Cloudflare Workers, Vercel Edge, Lambda@Edge). Rebuff, the only prior TypeScript-forward prompt-injection library, was archived on 2025-05-16 and depended on Pinecone and OpenAI calls at runtime.

### 2.2 Latency and footprint

Machine-learning-based detectors require transformer models that cannot fit in a 50 MB serverless cold-start budget and add 300 ms to multi-second overhead per request (NeMo Guardrails discussion #587 reports 3.5 – 11 s of overhead; Guardrails AI issue #791 reports 33 minutes for 10 prompts with the default `bart-large-mnli` classifier). No OSS library currently ships with sub-10 ms deterministic validation on commodity hardware.

### 2.3 Compliance mismatch

Application Security teams and internal auditors expect input-filtering controls to produce structured, SIEM-ready audit output mapped to published taxonomies. Existing OSS guardrails emit ad-hoc logs oriented toward ML observability (WhyLabs LangKit) rather than AppSec review. OWASP LLM Top 10 2025 was published in November 2024 and is increasingly referenced in SOC 2 CC6.6 and ISO 27001 A.14.2 audit matrices. No library ships this mapping natively.

### 2.4 LATAM coverage gap

Microsoft Presidio, the Python standard for PII recognition, requires per-locale spaCy model downloads and manually authored EntityRecognizers. It does not ship validators for DNI (Argentina), CPF / CNPJ (Brazil), CURP / RFC (Mexico), RUT (Chile), or cédula (Colombia). A library targeting LATAM deployments must provide these natively, including checksum validation where the identifier format defines it.

## 3. Non-goals for v0.1

- **Python SDK.** Deferred to v2.0 and conditional on Node.js traction. Dual-runtime is beyond the 12 h/week sustainable scope.
- **LLM-as-judge detection on the hot path.** Hackett et al. (arXiv:2504.11168, 2025) demonstrate 100% bypass of Azure Prompt Shield and Meta Prompt Guard via character injection. The v0.1 hot path is deterministic only. An optional ONNX classifier escalator is deferred to v0.5+ and is always opt-in and off the hot path.
- **Output validation.** Inspection of LLM responses is a distinct problem (token streaming, partial outputs, refusal templates). Deferred to v2.0. Output PII redaction is scoped for v0.2 as a narrower, tractable subset.
- **Hosted or managed service.** llm-waf is a library. A self-hosted audit-ingestion companion may appear in v1.5+ if demand materializes.
- **Content moderation / toxicity classification.** Well served by OpenAI Moderation (free) and Azure Content Safety. v0.2 ships an opt-in adapter for OpenAI Moderation rather than re-implementing.

## 4. Design principles

llm-waf commits to five architectural principles. Each is testable and defines the boundary of what the library accepts as a contribution.

### 4.1 Pure TypeScript, zero native dependencies

The v0.1 hot path uses only JavaScript primitives and Web APIs (TextEncoder, TextDecoder, URL, regular expressions, `crypto.subtle` for canary-token generation). No Python bridge, no transformer model load, no native addons, no post-install scripts. Ship as a pure ES module.

**Verifiable via:** `npm pack --dry-run` reports JS artifacts only; `npm install --ignore-scripts` produces an identical working tree; running on Cloudflare Workers with `nodejs_compat` disabled succeeds for the core.

### 4.2 Edge-runtime compatibility as a shipping gate

Every tagged release must pass a CI matrix that loads and exercises the library on Node.js ≥ 20, Bun ≥ 1.1, Deno ≥ 1.45, Cloudflare Workers (via Miniflare), and the Vercel Edge runtime (via `@edge-runtime/vm`). A feature that cannot run on any of these targets is excluded from v0.1.

**Verifiable via:** `.github/workflows/runtime-matrix.yml`.

### 4.3 Sub-10 ms P99 latency on deterministic checks

The v0.1 detectors (structural validation + regex + Unicode normalization + PII recognizers with checksum) MUST complete within 10 ms at the 99th percentile on commodity hardware (reference: Apple M-series or equivalent Linux x86-64, single-core, warm JIT) for prompts up to 2 000 UTF-8 characters. This budget excludes user business logic, network I/O, and any optional ML escalator.

**Verifiable via:** reproducible benchmark harness (`mitata`) with published fixtures and CI-enforced thresholds.

### 4.4 LATAM-first PII coverage

v0.1 ships deterministic recognizers (regex + checksum where applicable) for: DNI-AR, CPF-BR, CNPJ-BR, CURP-MX, RFC-MX, RUT-CL, cédula-CO. Each recognizer is documented with its format rule, checksum algorithm, and a reference test corpus covering valid, invalid, and near-miss inputs. Presidio parity for common international categories (email, credit card, IBAN, generic phone) is provided on a best-effort basis.

**Verifiable via:** test vectors published under `test/fixtures/pii/` with citations to issuing-authority format specifications.

### 4.5 Audit output as a first-class citizen

Every allow, block, or flag decision emits a structured event mapped to OWASP LLM Top 10 2025 identifiers and NIST AI RMF subcategories. The event schema is stable and documented. A JSON-lines sink ships in v0.1; OpenTelemetry and Splunk / Datadog sinks ship in v0.5 and v1.0 respectively.

**Verifiable via:** `test/audit-schema.test.ts` enforces schema stability across minor versions.

## 5. Architecture overview

llm-waf is organized as three layers.

### 5.1 Core (`llm-waf`)

Contains the detectors, PII recognizers, schema builder, audit event emitter, and Standard Schema adapter. Zero dependencies on framework integrations. Runs on any JavaScript runtime with Web APIs.

### 5.2 Framework adapters (v0.2+ as unbundled sub-packages)

- `@llm-waf/express` — Express middleware
- `@llm-waf/hono` — Hono middleware
- `@llm-waf/next` — Next.js Route Handler helper
- `@llm-waf/mcp` — Standard Schema integration for MCP servers (target: v0.5)

Each adapter is a thin shim over the core and declares adapter-specific types as peer dependencies.

### 5.3 Sinks (v0.2+ as unbundled sub-packages)

- `@llm-waf/sink-otel` — OpenTelemetry span exporter
- `@llm-waf/sink-splunk` — Splunk HEC exporter
- `@llm-waf/sink-datadog` — Datadog Logs exporter

Default built-in sink: JSON-lines to stderr.

### 5.4 Schema composition approach

Zod v4 does not provide an officially supported mechanism to inject chainable methods onto `z.string()` without prototype manipulation. The library therefore exposes a fluent builder (`waf.string()`, `waf.prompt()`) that emits a Zod v4 schema via `.build()` or implicit coercion. The resulting schema satisfies Standard Schema for downstream consumers (MCP v2, OpenAI Agents SDK, any library that accepts Standard Schema input).

Illustrative API (subject to SPEC.md refinement):

```ts
import { waf } from 'llm-waf';

const UserPrompt = waf.prompt({
  message: waf.string()
    .maxLength(2000)
    .noInjection()
    .noPII(['es-AR', 'pt-BR'])
    .noSecrets(),
  conversationId: waf.string().uuid(),
});

// Express integration
app.post('/chat', waf.middleware(UserPrompt), (req, res) => {
  // req.body is typed and already validated / redacted.
  // Audit events are emitted to the configured sink.
});
```

## 6. Trade-offs considered and rejected

### 6.1 Dual-runtime (Node.js + Python) — rejected

A solo maintainer with 12 h/week cannot ship a competitive Python SDK against Guardrails AI (≈ 6.6 k stars, $7.5 M seed, ≈ 200 k monthly PyPI downloads) and NVIDIA NeMo. The Node.js niche is empty; the Python niche is saturated. Opportunity cost of fighting on both fronts is verified failure.

### 6.2 LLM-as-judge detection on the hot path — rejected

Academic evidence (Hackett et al. 2025; HiddenLayer "Same Model, Different Hat") shows 100% bypass of judge models via targeted character injection. Simon Willison's 2024 observation that "95% is a failing grade for web application security" applies directly. Deterministic-first is the position; judge models can be used in out-of-band evaluation or CI-time red-teaming, not runtime defense.

### 6.3 Fork of Rebuff — rejected

Rebuff (archived 2025-05-16) depends on Pinecone, OpenAI calls, and LLM-as-judge primitives that the llm-waf architecture explicitly rejects. A fork would inherit 90% deletable code, require namespace negotiation with Palo Alto Networks (owner of `protectai/rebuff` via the Protect AI acquisition), and carry weaker branding than a clean-room start.

### 6.4 MCP-first API in v0.1 — rejected

The Model Context Protocol TypeScript SDK is in v2 pre-alpha as of April 2026 (v1 stable, v2 opt-in). Building on top of an unstable spec wastes v0.1 budget. Architectural commitment to MCP compatibility is public from day one; a Standard Schema adapter ships in v0.5 (target month 9) once MCP v2 stabilizes.

### 6.5 Generic naming (`prompt-shield`, `promptkit`) — rejected

The unscoped `prompt-shield` slug on npm is contested by three scoped or prefixed variants (`n8n-nodes-prompt-shield`, `@aiassesstech/prompt-shield`, `@ppcvote/prompt-shield`). For a library whose brand is a career-capital asset, category ownership matters more than name aesthetics. `llm-waf` was unclaimed, maps cleanly to the AppSec audience's mental model (Web Application Firewall), and translates without friction to Spanish ("WAF para LLMs").

## 7. Roadmap

### 7.1 v0.1 (target: month 7 – 8 / November – December 2026)

- Core structural validators (length, allowed characters, Unicode normalization, zero-width stripping)
- Deterministic prompt-injection heuristics (regex signature set, canary tokens, policy automata)
- PII recognizers: DNI-AR, CPF-BR, CNPJ-BR, CURP-MX, RFC-MX, RUT-CL, cédula-CO
- Audit event schema with OWASP LLM Top 10 2025 mapping
- Built-in JSON-lines sink
- Express adapter (`@llm-waf/express`)
- Reproducible benchmark harness
- English documentation; Spanish documentation for README and Quickstart

### 7.2 v0.2 (target: month 9 / January 2027)

- Hono adapter
- Next.js Route Handler adapter
- Output redaction (masking PII in LLM responses; narrower than full output validation)
- Optional OpenAI Moderation adapter for content filtering
- Additional PII recognizers expanding international coverage

### 7.3 v0.5 (target: month 10 / February 2027)

- MCP adapter (Standard Schema-based, targeting MCP v2)
- OpenTelemetry span sink
- Optional ONNX classifier escalator (off the hot path, opt-in)
- Published benchmark comparison vs `@guardrails-ai/core`, `@openai/guardrails`, and Arcjet

### 7.4 v1.0 (target: month 12 / April 2027)

- Splunk HEC and Datadog sinks
- Stable audit schema (1.0 compatibility contract)
- Two public case studies (one anonymized AppSec-at-scale deployment; one external LATAM adopter)
- First external conference talk (Ekoparty 2026 or equivalent)

## 8. Kill criteria

The project STOPs and pivots to contributor or maintainer of an upstream library under any of the following conditions, evaluated at month 6 (October 2026):

1. OpenAI bundles `openai-guardrails-js` into the default `openai` npm package, eliminating the standalone Node validator market for OpenAI-only users.
2. Guardrails AI ships a true-native `@guardrails-ai/core` that no longer requires a Python 3 subprocess on the host.
3. GitHub stars at month 6 below 150 **and** weekly npm downloads below 50 **and** no inbound adoption signals (issues, discussions, mentions in awesome-lists, blog references).

The fallback paths are (a) taking over an archived repo with community handoff (e.g., `deadbits/vigil-llm`, dormant since December 2023) or (b) contributing LATAM PII recognizers and OWASP audit mapping upstream to `openai-guardrails-js` or Arcjet to extract named-authorship career capital.

This criterion is non-negotiable. It protects against the failure mode of shipping a fifteenth-entrant generic validator with no defensible wedge.

## 9. Open questions

- **MCP v2 validator hook shape.** The exact interface for plugging a Standard Schema validator into an MCP server's tool-input pipeline is not yet finalized. Revisit when MCP v2 reaches beta; SPEC.md defers the adapter API design until then.
- **Checksum algorithms for less-documented LATAM identifiers.** Colombian cédula checksum rules vary by issuing era. Comprehensive test vectors need to be sourced from Registraduría Nacional del Estado Civil documentation.
- **Unicode normalization strategy.** NFKC vs NFC trade-offs for injection defense vs. legitimate non-Latin inputs (Arabic, CJK). SPEC.md specifies the default and the override API.
- **Canary-token binding scope.** Per-request, per-session, or per-conversation. Security-model implications analyzed in SPEC.md.

## 10. References

1. OWASP LLM Top 10 2025, November 2024. https://genai.owasp.org
2. NIST AI RMF Generative AI Profile (AI 600-1), July 2024.
3. EU AI Act (Regulation 2024/1689), Article 15.
4. Brazil PL 2338/2023 (Senate approved 2024-12-10).
5. Chile Boletín 16821-19 (Chamber approved 2025-10-13).
6. Greshake, Kai et al. "Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection." AISec '23. arXiv:2302.12173.
7. Perez, Fábio & Ribeiro, Ian. "Ignore Previous Prompt: Attack Techniques for Language Models." arXiv:2211.09527.
8. Hackett, William et al. "Bypassing LLM Guardrails." arXiv:2504.11168, 2025.
9. Chen, Sizhe et al. "StruQ: Defending Against Prompt Injection with Structured Queries." USENIX Security '25. arXiv:2402.06363.
10. Zod v4 Release Notes. https://zod.dev/v4
11. Model Context Protocol TypeScript SDK. https://github.com/modelcontextprotocol/typescript-sdk
12. Cloudflare Workers Node.js Compatibility. https://developers.cloudflare.com/workers/runtime-apis/nodejs/
