# Audit install scripts

Since npm v12 (and pnpm, yarn, and bun), dependency **install scripts don't run unless you allow them**. The question is: *which are safe?*

npm-script-lens answers with evidence. Open a `package.json` and every dependency whose install script spawns processes, reaches the network, or is flagged malicious gets a squiggle on its line:

```
"sharp": "^0.33.5",     🔴 HIGH — sharp@0.33.5: exec: node-gyp rebuild · exec: require('child_process')
"chalk": "^5.3.0",      (quiet — no install script)
```

The status bar shows the whole workspace's risk at a glance. Run **npm-script-lens: Audit install scripts** any time to refresh.
