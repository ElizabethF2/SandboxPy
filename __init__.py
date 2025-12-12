import sys, platform
from . import wasi

if platform.system() == 'Windows':
  from .windows import *
elif platform.system() == 'Linux':
  from .linux import *
elif platform.system() == 'Darwin':
  from .osx import *
elif platform.system() == 'FreeBSD':
  from .freebsd import *
else:
  run = wasi.run
  get_python_paths = lambda: []

def run_python(cmd,
               id,
               readable_paths=[],
               writable_paths=[],
               writable_paths_ensure_exists=[],
               env=None,
               cwd=None,
               **kwargs):
  exe = sys.executable
  if exe and not kwargs.get('force_wasi'):
    try:
      return run([os.path.abspath(exe)] + cmd,
                 id,
                 readable_paths = get_python_paths() + readable_paths,
                 writable_paths = writable_paths,
                 writable_paths_ensure_exists = writable_paths_ensure_exists,
                 env = env,
                 cwd = cwd)
    except FileNotFoundError:
      pass
  return wasi.run_python(cmd,
                         id,
                         readable_paths = readable_paths,
                         writable_paths = writable_paths,
                         writable_paths_ensure_exists = writable_paths_ensure_exists,
                         env = env,
                         cwd = cwd)
