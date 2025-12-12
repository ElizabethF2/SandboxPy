import subprocess, sys, os, re, shutil, threading, glob, json, stat
from . import util, wasi

_lock = threading.Lock()

class SandboxedProcess(subprocess.Popen): ...

# TODO kwargs for allow printing, allow mbox, maybe allow proot

def run(cmd,
        id,
        readable_paths = [],
        writable_paths = [],
        writable_paths_ensure_exists = [],
        env = None,
        cwd = None,
        **kwargs):
  bwrap = shutil.which('bwrap')
  if not bwrap or wasi.should_use_wasi(cmd[0], **kwargs):
    return wasi.run(cmd,
                    id,
                    readable_paths = readable_paths,
                    writable_paths = writable_paths,
                    writable_paths_ensure_exists = writable_paths_ensure_exists,
                    env = env,
                    cwd = cwd,
                    **kwargs)
  bcmd = [
    bwrap, 
    '--die-with-parent',
    '--dev', '/dev',
    '--proc', '/proc',
    '--tmpfs', '/tmp',
    '--dir', '/var',
    '--unshare-all'
  ]
  if kwargs.get('allow_networking'):
    bcmd.append('--share-net')
    bcmd += ('--ro-bind-try', '/etc/resolv.conf', '/etc/resolv.conf') # TODO
  for path in readable_paths:
    bcmd += ('--ro-bind-try', path, path)
  for path in writable_paths:
    bcmd += ('--bind-try', path, path)
  dir_keep_alive_handles = []
  for path in writable_paths_ensure_exists:
    dir_keep_alive_handles.append(util.ensure_dir_exists_and_get_keep_alive_handle(path))
    bcmd += ('--bind-try', path, path)
  proc = SandboxedProcess(
            bcmd + cmd,
            stdin = subprocess.PIPE,
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE,
            env=env,
            cwd=cwd,
          )
  proc.dir_keep_alive_handles = dir_keep_alive_handles
  return proc


def run_mbox(cmd, id, readable_paths=[], writable_paths=[], writable_paths_ensure_exists=[], env=None, cwd=None):
  import tempfile
  profile = os.path.join(tempfile.gettempdir(), 'sandbox_py_'+id+'.profile')
  profile_data = '[fs]\n'
  for path in readable_paths:
    profile_data += 'allow: ' + path + '\n'
  for path in writable_paths:
    profile_data += 'direct: ' + path + '\n'
  for path in writable_paths_ensure_exists:
    try: os.mkdir(path)
    except FileExistsError: pass
    profile_data += 'direct: ' + path + '\n'
  need_to_update_profile = False
  try:
    with open(profile, 'r') as f:
      if f.read() != profile_data:
        need_to_update_profile = True
  except FileNotFoundError:
    need_to_update_profile = True
  if need_to_update_profile:
    with open(profile, 'w') as f:
      f.write(profile_data)
  mcmd = ['mbox', '-i', '-n', '-p', profile]
  return SandboxedProcess(
           mcmd + cmd,
           stdin = subprocess.PIPE,
           stdout = subprocess.PIPE,
           stderr = subprocess.PIPE,
           env=env,
           cwd=cwd,
         )


python_paths = set()

def add_shared_object_paths_from_bins(bin_path):
  p = subprocess.run(['ldd', bin_path], capture_output=True)
  for line in p.stdout.splitlines():
    sp = line.decode().split()
    if os.path.isabs(sp[0]):
      util.add_path_if_unique(python_paths, sp[0])
    if len(sp) > 2:
      util.add_path_if_unique(python_paths, sp[2])

def parse_so_conf(path):
  if not os.path.exists(path):
    return
  with open(path, 'r') as f:
    for line in f:
      line = line.strip()
      if line.startswith('include '):
        pathname = line[8:]
        for path in glob.iglob(pathname, recursive=True):
          util.add_path_if_unique(python_paths, os.path.dirname(path))
          parse_so_conf(path)
      elif line and not line.startswith('#'):
        util.add_path_if_unique(python_paths, line)

def get_python_paths():
  with _lock:
    if len(python_paths) < 1:
      python_paths.add('/bin/sh')
      python_paths.add(sys.executable)
      has_ldd = shutil.which('ldd')
      if has_ldd:
        add_shared_object_paths_from_bins(sys.executable)

      # Get the paths of the files for every module
      # Run this in a new instance to avoid leaking any already imported, broker-only paths to the sandbox
      # socket, sqlite3 and threading are imported to ensure that paths for dynamically loaded modules are included in the sandbox
      code = ("import json,sys,socket,sqlite3,threading,ssl;print(json.dumps(" +
              "[[i.__file__ for i in filter(lambda i:hasattr(i,'__file__'),sys.modules.values())],sys.path]))")
      module_files, sys_path = json.loads(subprocess.run([sys.executable, '-c', code], capture_output=True).stdout)

      for file in filter(lambda i: i is not None, module_files):
        module_dir = os.path.dirname(file)
        util.add_path_if_unique(python_paths, module_dir)
        if os.stat(file).st_mode & stat.S_IXOTH:
          add_shared_object_paths_from_bins(file)

      for path in sys_path:
        if path and os.path.exists(path):
          util.add_path_if_unique(python_paths, path)

      # Needed for ctypes, which is used by pyseccomp
      for path in glob.iglob('/sbin/ldconfig*'):
        python_paths.add(path)
      bin_names = ('gcc', 'cc', 'ldconfig', 'objdump')
      for bin_name in bin_names:
        bin_path = shutil.which(bin_name)
        if bin_path:
          util.add_path_if_unique(python_paths, bin_path)
          if has_ldd:
            add_shared_object_paths_from_bins(bin_path)

      special_cases = [
        # glibc only lazy loads this library when canceling threads which is why
        # it doesn't show up in in the regular headers
        '/lib/libgcc_s.so*',
        '/lib64/libgcc_s.so*',
        '/usr/lib/libgcc_s.so*',
        '/usr/lib64/libgcc_s.so*',
      ]
      for pattern in special_cases:
        for path in glob.iglob(pattern):
          util.add_path_if_unique(python_paths, path)

      parse_so_conf('/etc/ld.so.conf')
      if os.path.exists('/etc/ld.so.cache'):
        util.add_path_if_unique(python_paths, '/etc/ld.so.cache')

    return list(python_paths)
