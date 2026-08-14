'use strict';
// Shell completion scripts for the CLI. `npm-script-lens completion <shell>`
// prints a sourceable script for bash / zsh / fish.

const COMMANDS = ['audit', 'allow', 'review', 'diff', 'sync', 'sources', 'publish', 'hooks', 'approve', 'manifest', 'doctor', 'init', 'mcp', 'completion'];
const FLAGS = [
  '--path', '--json', '--manager', '--policy', '--write', '--check', '--html', '--sarif',
  '--no-trust', '--no-cache', '--offline', '--deep', '--fail-on-high', '--ci-check', '--sync-check',
  '--diff', '--since', '--output-allowscripts', '--input', '--auto-fix', '--force', '--out', '--help',
  '--fail-on', '--deps', '--require-gate',
];

const bash = () => `# npm-script-lens bash completion. Add to ~/.bashrc:
#   source <(npm-script-lens completion bash)
_npm_script_lens() {
  local cur cmds flags
  cur="\${COMP_WORDS[COMP_CWORD]}"
  cmds="${COMMANDS.join(' ')}"
  flags="${FLAGS.join(' ')}"
  if [ "\$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=( \$(compgen -W "\$cmds --help --version" -- "\$cur") )
  else
    COMPREPLY=( \$(compgen -W "\$flags" -- "\$cur") )
  fi
}
complete -F _npm_script_lens npm-script-lens
`;

const zsh = () => `#compdef npm-script-lens
# npm-script-lens zsh completion. Add to your fpath, or:
#   source <(npm-script-lens completion zsh)
_npm_script_lens() {
  local -a cmds flags
  cmds=(${COMMANDS.map((c) => `'${c}'`).join(' ')})
  flags=(${FLAGS.map((f) => `'${f}'`).join(' ')})
  if (( CURRENT == 2 )); then
    compadd -- $cmds --help --version
  else
    compadd -- $flags
  fi
}
compdef _npm_script_lens npm-script-lens
`;

const fish = () => `# npm-script-lens fish completion. Save to:
#   ~/.config/fish/completions/npm-script-lens.fish
complete -c npm-script-lens -f
complete -c npm-script-lens -n __fish_use_subcommand -a "${COMMANDS.join(' ')}"
${FLAGS.filter((f) => f.startsWith('--')).map((f) => `complete -c npm-script-lens -l ${f.slice(2)}`).join('\n')}
`;

const SCRIPTS = { bash, zsh, fish };

function completionScript(shell) {
  const fn = SCRIPTS[shell];
  if (!fn) throw new Error(`unsupported shell '${shell}' (expected: ${Object.keys(SCRIPTS).join(', ')})`);
  return fn();
}

module.exports = { completionScript, COMMANDS, FLAGS };
