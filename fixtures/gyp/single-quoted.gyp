# GYP dialect stress fixture: single-quoted keys and values, `#` comments
# (including trailing ones), and trailing commas everywhere — none of which
# JSON.parse accepts.
{
  'variables': {
    'benign': '<(plain_var)', # plain interpolation — must NOT be flagged
    'arrays': '<@(also_plain)',
  },
  'targets': [
    {
      'target_name': 'stress', # trailing comment
      'type': 'none',
      'sources': [
        'src/a.c',
        'src/b.c',
      ],
    },
  ],
}
