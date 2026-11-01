---
name: okfw
description: Search garmr-policy-agent's OKF wiki (.okfw/) for project knowledge that is not in the code — design decisions and the reasoning behind them, security and dependency findings, operational and deployment context, open work, and orientation notes. Check here before deriving an answer from scratch or re-running an analysis. Use for "why is it built this way", "has X been considered before", "what do we know about Y", "what's the risk in Z". Also use to capture new notes, decisions, and daily journal entries.
---

# OKF Wiki (`okfw`)

The project keeps a local-first knowledge base in `.okfw/` at the project
root: markdown **concepts** with YAML frontmatter, woven together by links.

**The files are the whole database.** Search and the link graph are computed
from them on demand — there is no index to build and nothing to keep in sync,
so a concept is findable the moment it is written and gone the moment it is
deleted. This is the discovery model OKF describes: a consumer synthesizes the
view it wants by scanning frontmatter (section 3.1), and every directory carries
an auto-maintained `index.md` for progressive disclosure (section 8) — a cheap
way to see what a directory holds before opening anything in it.

If a command fails with "no OKF wiki found", run `okfw init` at the project
root first.

## Search before you derive

The wiki holds what the source does not say. Whenever a question could be
answered *either* by analysing the repository *or* by recalling a conclusion
someone already reached, search first — one `okfw_search` is far cheaper than
re-deriving, and the wiki may record a decision, caveat or measurement that
analysis alone cannot recover.

Search before you:

- explain **why** something is built the way it is, or what a constraint is for;
- propose a change that may already have been **considered and rejected**;
- assess **dependency, security or operational risk**;
- **run a scan or analysis** whose output someone may already have recorded
  *and adjudicated* — a recorded finding usually carries the reachability call,
  the false positives and the ranking that a fresh scan will not;
- write an **orientation** to unfamiliar code.

Each hit carries `trust` (`unverified`, `machine-confirmed`,
`human-reviewed`), plus `status` when it is `draft` or `deprecated` and `stale`
when its `stale_after` has passed. Weigh a hit by them: prefer a reviewed,
current concept, and treat a stale or deprecated one as a lead to check rather
than as the answer.

If the search returns nothing relevant, derive the answer normally — and
consider capturing what you learned.

## Interface

Each line gives the CLI form and the MCP tool. They are the same capability —
use whichever surface you have.

| do this | CLI | MCP |
|---|---|---|
| find concepts | `okfw search "query" --json` | `okfw_search {"q":"query"}` |
| search one directory | `okfw search --path <dir> --json` | `okfw_search {"dir":"<dir>"}` |
| list a directory | read `.okfw/<dir>/index.md` | `okfw_read {"ref":"<dir>/"}` (`"/"` for the root) |
| read one | — | `okfw_read {"ref":"<id or path>"}` |
| create one | `okfw create "Title" --body "..." --json` | `okfw_create {"title":"Title","body":"..."}` |
| create an issue | `okfw create "Title" --kind issue --json` | `okfw_create {"kind":"issue","title":"Title"}` |
| today's journal | `okfw daily` | `okfw_create {"kind":"daily"}` |
| edit metadata or body | `okfw set-lifecycle` / `verify` / `add-source` / … | `okfw_update {"ref":…,"action":…,"value":…}` |
| swap a tag | `okfw remove-tags <ref> open` then `okfw add-tags <ref> resolved` | `okfw_update` actions `remove_tags`, `add_tags` |
| what links here | `okfw backlinks <ref> --json` | `okfw_graph {"action":"backlinks","ref":…}` |

CLI only: `okfw init`, `okfw move`, `okfw delete`, `okfw validate --all`,
`okfw graph`, `okfw graph-query`, `okfw install`. Every command is
self-documenting (`okfw <cmd> --help`) and read commands support `--json`.

Results are capped and say so. A `truncated` field, or a `… N more` line,
means you did not see everything — raise `--limit` / `"limit"`, or page with
`--offset` / `"offset"`. `okfw_read` returns 200 lines by default; narrow with
`section`, or page with `offset`/`limit`.

## Conventions that matter

1. **Link actively — links are the product.** OKF section 6.1 treats every link
   as a directed edge, which is what `backlinks` and `okfw graph` traverse.
   Connect related concepts with
   plain markdown links using wiki-relative targets:
   `[Display Title](/research/protocols/deep-note--019f23d3.md)` (leading `/`
   = wiki root; `./relative.md` also works). Links power `backlinks` and the
   graph. A new concept should link to at least one existing concept when a
   relation exists — search first to find candidates.
2. **One idea per concept.** Small, atomic, densely linked notes beat long
   documents. Split rather than append unrelated content.
3. **Write a `description`.** The one-sentence description is what a search
   hit shows and what the auto-generated `index.md` listings render.
4. **Organize with `dir`/`--path`** (e.g. `research/protocols`) for topical
   subdirectories, and optional `project` metadata for cross-cutting
   filtering. Untouched, notes land at the wiki root — that's fine.
5. **Daily notes are for capture** (`daily/YYYY/MM/`), one per day,
   idempotent. Refine durable ideas out of them into their own concepts, then
   link.
6. **Mark superseded knowledge rather than deleting it.** `status` is the OKF
   lifecycle field — `draft`, `stable` (the default when absent), or
   `deprecated`. Set it with `okfw set-lifecycle` / `okfw_update` action
   `set_lifecycle`, and `stale_after` when a concept has a known shelf life.
   okfw has **no task-tracking fields**; `status` is lifecycle only.
7. **Cite where knowledge came from** with `okfw add-source --resource <uri>`
   / `okfw_update` action `add_source`, and record review with `okfw verify` /
   action `verify`. Custom metadata goes under the `x:` frontmatter block — it
   is the only place unrecognized keys are accepted, as the schema is
   otherwise closed and will reject a typo'd field.
8. **Never blend what a source says with what you concluded from it** unless the
   boundary is visible on the page. A concept recording a decision, an incident
   or a measurement is read later as *the record*, by people and agents alike,
   and neither can tell your inference from the thing you are citing. Put your
   own assessment under its own heading that says so ("Analysis — not part of
   the recorded decision"), or attach it to a `[^id]` footnote keyed to a
   `sources[]` entry. A concept that mixes the two silently turns a reader's
   opinion into the project's official reasoning the next time anyone asks.
   Add the source (`okfw add-source --id <label>` / `okfw_update` action
   `add_source`) before writing the claim that cites it: a `[^label]` matching
   no source and no definition is refused.
9. **Reorganize with `okfw move`, not `mv`.** It keeps the concept's `id`,
   retargets every inbound link, and fixes the moved concept's own relative
   links; moving the file yourself silently breaks both. `okfw delete`
   reports the inbound links it leaves behind and refreshes the `index.md`
   listings that a plain `rm` would leave stale. Deleting leaves inbound links
   dangling on purpose — OKF tolerates them.
10. **Don't edit `index.md` or `log.md`** — they are reserved, generated files
   owned by okfw.

## Workflow

**Retrieving.** Start from a listing when you do not know the wiki yet
(`okfw_read {"ref":"/"}`, then a directory): each entry shows the concept's
description, so you open only what fits. Search → read the hits worth reading (`okfw_read` with a
`section` beats reading whole concepts) → follow their links and `backlinks`,
since a relevant concept usually neighbours others → *then* fall back to source
or fresh analysis for whatever the wiki did not cover.

**Capturing.** Capture quickly → refine → link. Over MCP, set `type`,
`status`, `stale_after`, `resource` and `generated_by` in the `okfw_create`
call itself: one write, no follow-up updates. Before creating, search to
avoid duplicates and to find concepts the new note should link to. Edits made
outside okfw need no follow-up command — search and the graph read the files
directly. Only the `index.md` listings are generated, and every okfw mutation
refreshes them.
