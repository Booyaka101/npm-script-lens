# Audit install scripts

Since npm v12 (and pnpm, yarn, and bun), dependency **install scripts don't run unless you allow them**. The question is: *which are safe?*

npm-script-lens answers with evidence. Open a `package.json` and every dependency whose install script spawns processes, reaches the network, or is flagged malicious, **and that you have not yet ruled on**, gets a squiggle on its line:

```
"sharp": "^0.33.5",     sharp@0.33.5 runs code when you install it: runs other
                        programs and reads your environment variables. You have
                        not approved or blocked it yet.
"chalk": "^5.3.0",      (quiet, no install script)
```

Hover it and you get the lifecycle command it runs (`install → node-gyp rebuild`), the raw signals behind each claim, who published the version and when, and two buttons: **Approve** or **Block**. Same two on <kbd>Ctrl</kbd>+<kbd>.</kbd>. Whichever you pick is written into your package manager's own allowlist as an ordinary, undoable edit.

Risk that arrives **transitively** (a package you never typed, pulled in by one you did) is anchored on the dependency that brought it in, tagged `pulled in by …`. That is the line you can actually act on.

The **Install scripts** panel in the activity bar lists all of them at once, including the ones with no line anywhere in your `package.json`, grouped by what is left to decide.

Once a package is in your allowlist the warning goes away, because you answered it. A deliberate override of a HIGH stays visible as a note rather than a warning; a known-malicious package stays an error no matter what the allowlist says.

The status bar leads with how many packages still need a ruling. Run **npm-script-lens: Audit install scripts** any time to refresh.
