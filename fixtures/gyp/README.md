# gyp fixtures

Real build files, used by `test/gyp.test.js`.

| file | what it is |
|---|---|
| `benign-bufferutil.gyp` | `bufferutil@4.0.9`'s real `binding.gyp`, verbatim. Contains a genuine `<!(cc -v …)` command expansion **and** a plain `<(clang_version)` reference — the true-positive/false-positive pair the scanner must separate. |
| `malicious-miasma.gyp.template` | the June 2026 Miasma payload's real *structure* ([ReversingLabs, 2026-06-04](https://www.reversinglabs.com/blog/npm-bindinggyp-cicd-secrets)), with the command replaced by `__CMD__`. See the note below. |
| `evasive-late.gyp` | the one-character evasions: `>!(`, `^!@(`, `<\|(`, `<!pymod_do_main(`. |
| `include-parent.gyp` + `deps/common.gypi` | payload lives only in the included `.gypi`, modelled on `better-sqlite3@11.10.0`. |
| `single-quoted.gyp` | GYP dialect stress: single quotes, `#` comments, trailing commas — none of which `JSON.parse` accepts. |

## Why the Miasma fixture is a template and not a `.gyp` file

Because it is the **real published payload**, antivirus treats it as live malware.
Committing it as a plain file breaks the test suite on any Windows machine:

- Windows Defender quarantined `fixtures/gyp/malicious-miasma.gyp` off disk
  (`Trojan:JS/PhantomWorm.DA!MTB`) — reproduced 2026-07-27; the file vanished
  mid-run and reddened five tests.
- Storing it base64-encoded did **not** help: Defender decodes containers and
  matched anyway (`…gyp.b64->(Base64)`).

So the structure lives here and the command lives in the test, and the test
joins them at runtime. **The scanner still runs over the exact original bytes** —
nothing about the coverage is weakened; only the on-disk representation changed.
Please don't "tidy" this back into a single file: it will pass on Linux, then
delete itself on Windows and in CI.
