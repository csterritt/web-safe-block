# web-safe-block — system atlas

An explorable map of the system plus its text twin. One data file is the source of truth; both views are generated from it.

| File | Role | Edit it? |
|---|---|---|
| `data.mjs` | Single source of truth: structures, flows, chapters, decisions, questions, prose | Yes |
| `template.html` + `build.mjs` | Renderer + generator (from the `system-atlas` skill) | Presentation only |
| `atlas.html` | Built interactive atlas — open in a browser | No (generated) |
| `SYSTEM.md` | Built text twin: decisions, every structure, flows, question index | No (generated) |
| `CONTEXT.md` | Glossary (the nouns, one line each) | By hand |
| `adr/` | Hard-to-reverse decisions | By hand |
| `research/` | Evidence the atlas is based on | Append-only |

## Rebuild

```sh
bun Notes/atlas/build.mjs    # rewrites SYSTEM.md and atlas.html beside data.mjs
```

After editing `data.mjs`, rebuild and reopen `atlas.html`. Never hand-edit the generated files.

## Viewing

`atlas.html` is self-contained. Serve the folder rather than opening `file://` (some in-app browsers render file URLs as static snapshots):

```sh
cd Notes/atlas && python3 -m http.server 8777   # then http://localhost:8777/atlas.html
```

Keys: `enter`/`]` next chapter, `[` back, hover to read, click to pin, `→` go inside, `←` come out, click a packet dot to inspect.
