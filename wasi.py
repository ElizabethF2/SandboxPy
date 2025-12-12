import os, subprocess, tempfile, shutil, hashlib, stat
from . import util

DEFAULT_WASI_PYTHON = 'python/python'

class SandboxedProcess(subprocess.Popen):
  pass

def is_wasi_or_wasix(path):
  try:
    with open(path, 'rb') as f:
      buf = f.read(5)
      if buf[:4] == b'\x00asm':
        return True
      if buf == b'\x00webc':
        return True
  except FileNotFoundError:
    pass
  return False

def should_use_wasi(path, **kwargs):
  if kwargs.get('force_wasi'):
    return True
  return path == os.path.isabs(path) and is_wasi_or_wasix(path)

def get_mirror_dir():
  d = 'sandboxpy_wasi'
  try:
    import getpass
    d += '_' + getpass.getuser()
  except ModuleNotFoundError:
    pass
  return os.path.join(tempfile.gettempdir(), d)

def try_cleanup_mirror_dir(md, mp):
  if len(mp) == 0:
    try:
      shutil.rmtree(md)
    except FileNotFoundError:
      pass
    try:
      os.rmdir(os.path.dirname(md))
    except OSError:
      pass

def run(cmd,
        id,
        readable_paths=[],
        writable_paths=[],
        writable_paths_ensure_exists=[],
        env=None,
        cwd=None,
        wasi_dependencies=[],
        mirror_readable_paths=False,
        **kwargs):
  wasmer = shutil.which('wasmer')
  if not wasmer:
    wasmtime = shutil.which('wasmtime')
    try:
      from . import pywasix
      return pywasix
    except ModuleNotFoundError:
      pass
  if not wasmer and not wasmtime:
    raise FileNotFoundError('Unable to find sandbox utilities or runtimes')
  mp = {}
  md = os.path.join(get_mirror_dir(), hashlib.sha256(id).hexdigest())
  if len(readable_paths) > 0:
    for path in readable_paths:
      try:
        st = os.stat(path)
        if not mirror_readable_paths:
          raise ValueError('Cannot use readable_paths with wasi when mirror_readable_paths is false')
        try_cleanup_mirror_dir(md, mp)
        _, _, tail = os.path.splitroot(path)
        mpath = os.path.join(md, tail)
        if stat.S_ISDIR(stat.st_mode):
          shutil.copytree(path, os.path.join, dirs_exist_ok = True)
        else:
          os.makedirs(os.path.dirname(mpath), exist_ok = True)
          shutil.copy2(path, mpath)
        mp[path] = mpath
      except FileNotFoundError:
        pass
  try_cleanup_mirror_dir(md, mp)
  dir_keep_alive_handles = []
  if wasmer:
    wcmd = [wasmer, 'run', '--net=ipv4:deny=*:*,ipv6:deny=*:*,dns:deny=*:*']
  else:
    wcmd = [wasmtime]
  for path, mpath in mp.items():
    wcmd += ['--mapdir' if wasmer else '--dir', path+'::'+mpath]
  for path in writable_paths:
    try:
      st = os.stat(path)
      if stat.S_ISDIR(st.st_mode):
        mpath = path
      else:
        _, _, tail = os.path.splitroot(path)
        mpath = os.path.join(md, tail)
        os.makedirs(os.path.dirname(mpath), exist_ok = True)
        os.symlink(os.path.abspath(path), mpath)
      wcmd += ['--mapdir' if wasmer else '--dir', path+'::'+mpath]
    except FileNotFoundError:
      pass
  for path in writable_paths_ensure_exists:
    h = util.ensure_dir_exists_and_get_keep_alive_handle(path)
    dir_keep_alive_handles.append(h)
    wcmd += ['--mapdir' if wasmer else '--dir', path+'::'+path]
  if wasmer:
    for dependency in wasi_dependencies:
      wcmd += ['--use', dependency]
  if env is not None:
    for k,v in env.items():
      wcmd += ['--env', str(k)+'='+str(v)]
  if wasmer:
    wcmd += [cmd[0], '--'] + cmd[1:]
  else:
    wcmd += cmd
  proc = SandboxedProcess(
          wcmd,
          stdin = subprocess.PIPE,
          stdout = subprocess.PIPE,
          stderr = subprocess.PIPE,
          cwd=cwd,
        )
  proc.dir_keep_alive_handles = dir_keep_alive_handles
  return proc

def run_python(cmd,
               id,
               readable_paths=[],
               writable_paths=[],
               writable_paths_ensure_exists=[],
               env=None,
               cwd=None,
               wasi_dependencies=[],
               mirror_readable_paths=False,
               wasi_python=None,
               wasi_python_readable_paths=None,
               **kwargs):
  if wasi_python is None:
    wasi_python = os.environ.get('WASI_PYTHON', DEFAULT_WASI_PYTHON)
  if wasi_python_readable_paths is None:
    wasi_python_readable_paths = os.environ.get('WASI_PYTHON_READABLE_PATHS', [])
  return run([wasi_python] + cmd,
             id,
             readable_paths = wasi_python_readable_paths + readable_paths,
             writable_paths = writable_paths,
             writable_paths_ensure_exists = writable_paths_ensure_exists,
             env = env,
             cwd = cwd,
             wasi_dependencies = wasi_dependencies,
             mirror_readable_paths = mirror_readable_paths,
             **kwargs)

def delete_all_sandboxes():
  try:
    shutil.rmtree(get_mirror_dir())
  except FileNotFoundError:
    pass
