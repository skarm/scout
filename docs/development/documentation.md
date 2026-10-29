# Documentation conventions

English · [Русский](documentation.ru.md)

Keep English `.md` and Russian `.ru.md` guides together. Update both when commands,
contracts or examples change. Language links select the matching page; internal
manual links stay in the current language. Go source comments use English.

## GoDoc

Follow [Go doc-comment conventions](https://go.dev/doc/comment). Start with the
exported symbol's name and explain its contract. Each package has one description
beginning with `Package name`.

Document exported functions, methods, interface methods, types, constants, variables
and struct fields. Explain results, relevant errors, ownership, cancellation,
concurrency and meaningful zero values. State field units, coordinate conventions
and limit scope. Comment private helpers where an invariant or design choice needs explanation.

## Writing

Preserve technical meaning, identifiers, quantities, conditions and uncertainty.
Use direct verbs, one topic per paragraph and one action per instruction.
Keep README focused on getting started; place protocol and implementation details
in the relevant reference guide. Remove repeated explanations.

Add a table of contents to a long guide when it helps navigation. Do not add
contents blocks to Go source files. Preserve directives, quotations and legal text.

## Verification

Run `gofmt`, inspect `go doc`, and check links, anchors and EN/RU pairs.
Documentation edits must preserve behavior, except changes needed to package the
documentation itself. Source-bound receipts need fresh evidence after Go file edits;
see [acceptance](validation.md#binary-and-source-acceptance).
