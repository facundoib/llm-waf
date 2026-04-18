# llm-waf

TypeScript-native Web Application Firewall for LLM inputs. Deterministic prompt injection defense, LATAM-first PII redaction, and OWASP LLM Top 10-mapped audit output. Edge-runtime compatible.

## Status

Pre-alpha. Specification in progress. Not ready for use.

RFC and v0.1 spec are being drafted. Follow the repository for updates.

## Goals (v0.1)

- Pure TypeScript. Zero Python. Zero machine-learning dependencies on the hot path.
- Runs on Node.js, Cloudflare Workers, Vercel Edge, Bun, and Deno.
- Zod-composable declarative API.
- LATAM-first PII recognizers (DNI, CPF, CNPJ, CURP, RFC, RUT, cédula).
- Structured audit output mapped to OWASP LLM Top 10 2025 and NIST AI RMF.
- MCP-compatible by design; adapter shipping in v0.5.

## Non-goals (v0.1)

- Python SDK (deferred; conditional on Node.js traction).
- LLM-as-judge detection on the hot path.
- Output validation (deferred to v2.0).
- Hosted or managed service.

## License

Apache-2.0

## Maintainer

[Facundo Ibarzabal](https://github.com/facundoib)
