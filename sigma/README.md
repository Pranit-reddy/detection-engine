# Sigma versions of three rules

[Sigma](https://github.com/SigmaHQ/sigma) is the open, vendor-neutral rule format
most detection teams share rules in. This project's own YAML format is a smaller
format designed to be evaluated directly by `engine.py`. These three files show how
three of its rules translate to Sigma, and where the translation is not clean.

| File | Original rule | What it demonstrates |
|---|---|---|
| `browser_spawns_shell.yml` | `rules/browser_spawns_shell.yml` | A clean 1:1 translation |
| `lsass_process_access.yml` | `rules/lsass_process_access.yml` | A feature Sigma lacks (bitmask) |
| `discovery_recon_burst.yml` | `rules/discovery_recon_burst.yml` | Thresholds become correlation rules |

## Operator mapping

| This project | Sigma |
|---|---|
| `equals`, `equals_any` | plain field value or list |
| `contains_any` | `Field\|contains: [..]` |
| `contains_all` | `Field\|contains\|all: [..]` |
| `not_contains` | a `filter_*` selection, then `condition: selection and not filter` |
| `logsource.channel` / `provider` | `logsource: {category, product}` (see below) |
| `bitmask_any` / `bitmask_none` | **no equivalent** |
| `threshold` | a separate `correlation` rule of type `value_count` |

Sigma describes a log source abstractly (`category: process_creation`) and leaves a
backend to map it to a concrete channel and Event ID. This project names the
channel and Event ID directly, which is simpler but less portable.

## Where the translation is lossy

- **Bitmask matching.** Sigma cannot say "any of these access-right bits is set".
  The LSASS rule instead lists the six exact `GrantedAccess` values the original
  matched across the sample corpus. It will miss a tool that requests a
  combination of rights not on that list, so it is an approximation of the
  original, not an equivalent.
- **Thresholds.** The original counts distinct binaries per capture file, because
  the corpus has no timeline. The Sigma version is a correlation grouped by
  `Computer` over a 10 minute window. That is closer to how this would run on live
  telemetry, but the window length is an assumption and has not been tuned.

## What was checked

- All three files parse with [pySigma](https://github.com/SigmaHQ/pySigma) with no
  errors, and the second document in `discovery_recon_burst.yml` is recognised as a
  correlation rule.
- Using a throwaway evaluator, `browser_spawns_shell` and `lsass_process_access`
  hit exactly the same sample files as their originals (4 and 13 of 278).
- The correlation rule was checked for syntax only. It could not be run against
  this corpus.
