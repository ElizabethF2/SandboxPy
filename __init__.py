import sys, platform

if platform.system() == 'Windows':
  from sandbox.windows import *
elif platform.system() == 'Linux':
  from sandbox.linux import *
elif platform.system() == 'Darwin':
  from sandbox.osx import *
elif platform.system() == 'FreeBSD':
  from sandbox.freebsd import *
else:
  def run(*args, **kwargs):
    raise NotImplementedError('Unsupported platform')
  get_python_paths = run

def run_python(cmd, id, readable_paths=[], writable_paths=[], writable_paths_ensure_exists=[], env=None, cwd=None):  
  return run([sys.executable] + cmd,
             id,
             readable_paths = get_python_paths() + readable_paths,
             writable_paths = writable_paths,
             writable_paths_ensure_exists = writable_paths_ensure_exists,
             env = env,
             cwd = cwd)
