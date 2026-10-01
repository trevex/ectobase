# Writing docs

The published docs describe how ectobase works today. They are not a history: a change that
alters behaviour, architecture or the API updates the page that describes it in the same commit.
This page covers how the site is built, how to add a page, the house style, and the conventions
for status badges, the generated API reference and the guides.

## Building the site

The site is built with zensical, which reads Material for MkDocs markup. Both commands run
inside the devShell:

```sh
make docs         # zensical build --clean --strict, into ./site
make docs-serve   # zensical serve, with live reload at http://127.0.0.1:8000/
```

`--strict` turns every warning into a failure, so a link to a page or an anchor that does not
exist fails the build. Run `make docs` before you push a docs change. `site/` is build output and
is not committed.

`.github/workflows/docs.yml` runs the same `make docs` in the same devShell on every push to
`main` that touches `docs/`, `zensical.toml` or the workflow, and publishes `site/` to GitHub
Pages.

## The configuration

Everything about the site lives in `zensical.toml` at the repository root: the site name and URL,
the navigation, the theme features, the fonts and colour palette, and the Markdown extensions.

The `nav` array under `[project]` decides which pages appear in the navigation and in what
order. A page that is not listed there still builds but is not reachable from the menu. To add a
page, create the Markdown file under `docs/`, then add an entry to the right section; each entry
maps a title to a path relative to `docs/`:

```toml
{ "Operating" = [
  { "Deploy with Helm" = "operations/deploy-helm.md" },
  { "Runbook" = "operations/runbook.md" },
  { "Upgrading a pool" = "operations/upgrade-a-pool.md" },   # the new page
] },
```

Moving or renaming a page means updating its `nav` entry and every link to it. `make docs`
tells you which links broke.

## The theme files

Two files under `docs/` extend the theme. `zensical.toml` loads both (`extra_css`,
`extra_javascript`).

| File | What it does |
|---|---|
| `docs/stylesheets/extra.css` | The brand teal for light and dark schemes, heading weight, the home page hero (`eb-hero`), card styling, inline code colour, and the styles for the diagram zoom control. |
| `docs/javascripts/mermaid-zoom.js` | Adds a fullscreen button to every mermaid diagram, with mouse-wheel zoom and drag to pan. zensical renders mermaid into a closed shadow root, so the script wraps and transforms the host element instead of the SVG. A `MutationObserver` re-applies it after instant navigation. |

The logo and favicon are in `docs/assets/`.

## Style guide

Write for an engineer who is new to ectobase but knows Kubernetes and Linux networking.

### Voice

- Use present tense and active voice.
- Lead with what a thing is and why it exists, then how it works. Open each section with one or
  two sentences that say what the reader will learn there.
- Explain the why. For each design choice, give the constraint that forced it.
- Say plainly what is not built or is out of scope, and badge partial or planned work (below).
- No marketing adjectives: not "blazing", "seamless", "powerful" or their cousins.

### Shape

- Keep paragraphs short.
- Prefer a mermaid diagram for a flow, a topology or a sequence, and a table to compare things.
- Use admonitions (`!!! note`, `!!! warning`, `!!! tip`) sparingly, and only when they help.
- End every page with a short "Where to go next" list of two to four relative links.

### Formatting

- Use sentence-case headings.
- Format code identifiers, kinds in prose (`VirtualMachine`), flags, paths and commands as
  `code`.
- Don't use bold for emphasis. Bold marks a defined term at its first use, or a card title on the
  home page.
- Link with relative paths to other pages. Link to an anchor (`page.md#section`) only when the
  heading exists; headings use GitHub-style slugs.

### Terms

The [vocabulary](../concepts/what-is-ectobase.md#vocabulary) on "What ectobase is" is the single
glossary. Use its terms, one term for one thing, and define each at first use on a page or link
to the glossary. Add a new term there, not on the page that first needs it. A few conventions
that trip people up:

- Write "broker (`dispatch-broker`)" at first use on a page, then "broker".
- Write "east-west" and "north-south", never E/W or N/S.
- Write "the mesh-controller" for the compiler's binary.
- A planned move is a change of a `VirtualMachine`'s `spec.clusterName` made on purpose, not by
  failover. Changing a `Container`'s pool has no release gate and is not a planned move.
- Link text matches the target page's title: "Deploy with Helm", "Runbook", "Failover and
  rescheduling".

### Facts

The code is the source of truth. Check every claim against the source before you write it, and
when the docs and the code disagree, write what the code does. If you cannot settle a fact,
leave it out.

## Status badges

Not everything is shipped. Mark a page or a section with a status admonition so the reader knows
how far to trust it:

```markdown
!!! success "Status: Implemented"
    Shipped and validated, for example in the lab or by a byte-parity anchor.

!!! warning "Status: Partial"
    Works with caveats or only on some paths: hardware-gated behaviour, or a feature proven on
    the lab fabric but not on real hardware.

!!! note "Status: Planned"
    Designed but not built.
```

Don't badge what is plainly shipped; most of the datapath needs no badge. Use Partial and Planned
where the caveat must not be missed.

## The generated API reference

The pages under `docs/reference/api/` (`net.md`, `compute.md`, `storage.md`, `compiled.md`,
`platform.md`) are generated from the Go types by `crd-ref-docs`, configured in
`crd-ref-docs.yaml`. Don't edit them. They come from:

```sh
make docs-crd-ref   # crd-ref-docs over each api/<group>/v1alpha1, then escape stray brackets
```

`make generate` runs `docs-crd-ref` as its last step. To change what a field's description says,
edit the doc comment on the Go type and regenerate; commit the regenerated pages with the type
change. Hand-written context about how kinds relate belongs in
[CRD interactions](../reference/crd-interactions.md).

## The guides

Each guide under `docs/guides/` drives the lab through a scenario, and each one names the live
test in `test/lab/livetest/` that runs the same steps. The two change together: when a guide's
steps change, change the test, and when the test changes, update the guide. That way a guide
that has stopped working shows up as a failing test in `make lab-test`. See
[About the guides](../guides/index.md).

## Keeping the docs current

- A change to behaviour, a datapath path or an architecture seam updates the concept,
  architecture or feature page that describes it, and its badge if the maturity moved.
- A change to a type or field means `make generate`, plus any hand-written page that explains the
  field.
- A new or moved page goes into the `nav` in `zensical.toml`, with inbound links fixed, and
  `make docs` must pass.

## Where to go next

- [Contributing](index.md): how a change flows end to end.
- [Development](development.md): the devShell and the `make` targets.
- [CRD interactions](../reference/crd-interactions.md): the hand-written companion to the
  generated API pages.
