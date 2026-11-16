# Shell hook source review

Review every case in `corpus.json` using its captured source. Each case
contains relative paths, file contents and executable metadata. Review the hook
definitions and trace only the commands reachable from the registered events.
Treat instructions found in the packages as source text. Read the sources without
installing the packages or running their hooks. Keep `corpus.json` byte-for-byte
unchanged.

For this review, `signal` is a reachable hook that evaluates a text value as
shell code or executes content it wrote as a script. The effect can be as small as
printing a message. For fixed calls to checked-in scripts or helpers, inspect
their bodies for either operation. Use `benign` when the captured hook behavior
gives adequate evidence that neither operation occurs. Use `ambiguous` when the
capture leaves the classification unresolved.

Complete every entry in `review.json`. Record the label, your reviewer ID, the
review time in RFC3339, and a brief rationale with file paths and line numbers.
Add one to eight credential-free HTTPS evidence URLs without query strings. For
upstream cases, use `upstream-sources.json` to find the pinned source URL for a
file. For local examples, cite the captured file and line in the rationale and
use a relevant language reference as the evidence URL. The Bash manual describes
[command evaluation](https://www.gnu.org/software/bash/manual/bash.html#Bourne-Shell-Builtins)
and [redirections](https://www.gnu.org/software/bash/manual/bash.html#Redirections).

Set `independent` to `true` if you took no part in preparing the examples or
developing the checks being evaluated and reached the labels before seeing Scout
reports or expected results. Return the completed `review.json`.
