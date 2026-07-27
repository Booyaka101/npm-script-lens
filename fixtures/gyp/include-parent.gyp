# Modeled on better-sqlite3@11.10.0's binding.gyp: the parent looks clean and
# defers to deps/common.gypi — which is where the payload hides.
{
  'includes': ['deps/common.gypi'],
  'targets': [
    {
      'target_name': 'parent',
      'sources': ['src/clean.c'],
    },
  ],
}
