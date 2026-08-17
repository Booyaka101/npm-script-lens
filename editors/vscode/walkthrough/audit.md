# Audit install scripts

Since npm v12 (and pnpm, yarn, and bun), dependency **install scripts don't run unless you allow them**. The question is: *which are safe?*

npm-script-lens answers with evidence. Open a `package.json` and every dependency whose install script spawns processes, reaches the network, or is flagged malicious, **and that you have not yet ruled on**, gets a squiggle on its line:

```
"sharp": "^0.33.5",     🔴 HIGH sharp@0.33.5: exec: node-gyp rebuild · exec: require('child_process')
                             · undecided, run “npm-script-lens: Generate allowlist”
"chalk": "^5.3.0",      (quiet, no install script)
```

Risk that arrives **transitively** (a package you never typed, pulled in by one you did) is anchored on the dependency that brought it in, tagged `(via …)`. That is the line you can actually act on.

Once a package is in your allowlist the warning goes away, because you answered it. A deliberate override of a HIGH stays visible as a note rather than a warning; a known-malicious package stays an error no matter what the allowlist says.

The status bar leads with how many packages still need a ruling. Run **npm-script-lens: Audit install scripts** any time to refresh.
