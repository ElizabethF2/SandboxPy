import os, sys, platform, errno, pdb

STRICT_SYSCALL_WHITELIST = ['openat', 'read', 'write', 'fstat', 'pwrite64', 'pread64', 'fsync', 'fdatasync', 'close', 'lseek', 'exit', 'exit_group', 'brk', 'mmap', 'mprotect', 'poll', 'select', 'clock_nanosleep', 'nanosleep', 'fork', 'clone', 'getrandom', 'futex']

DEFAULT_SYSCALL_WHITELIST = STRICT_SYSCALL_WHITELIST + ['open', 'openat', 'stat', 'lstat', 'getdents', 'getdents64', 'rename', 'unlink', 'unlinkat', 'mkdir', 'rmdir', 'chdir', 'fchdir', 'getcwd', 'access', 'fcntl', 'execve', 'uname', 'pipe', 'pipe2', 'dup', 'dup2', 'dup3', 'set_tid_address', 'set_robust_list', 'sigaction', 'rt_sigaction', 'seccomp']

ARBITRARY_LARGE_ID = 32334

PATH_EXCEPTIONS = []

def enable_seccomp(syscall_whitelist=DEFAULT_SYSCALL_WHITELIST):
  try:
    import seccomp
  except ImportError:
    import pyseccomp as seccomp

  filter = seccomp.SyscallFilter(seccomp.ERRNO(errno.EACCES))
  if platform.machine() == 'AMD64':
    filter.add_arch(seccomp.Arch.X86)
  for i in syscall_whitelist:
    filter.add_rule(seccomp.ALLOW, i)
  filter.load()
  return filter


def enable_default_seccomp():
  enable_seccomp(DEFAULT_SYSCALL_WHITELIST)


def enable_strict_seccomp():
  enable_seccomp(STRICT_SYSCALL_WHITELIST)


def enable_capsicum():
  import pycapsicum
  pycapsicum.enter()


def clear_environment_variables():
  os.environ.clear()


def is_potential_path(path):
  try:
    path = path.decode()
  except (AttributeError, TypeError, UnicodeDecodeError, OSError):
    pass
  if not type(path) is str:
    return False
  return (':\\' in path or path.startswith('/') or path.startswith('\\\\')) and path not in PATH_EXCEPTIONS


def remove_potential_paths_from_object(obj):
  for a in dir(obj):
    try:
      v = getattr(obj, a)
    except AttributeError:
      continue # Ignore __abstractmethods__ et al
    try:
      if is_potential_path(v):
        setattr(obj, a, '' if type(v) is str else b'')
      elif hasattr(v, 'clear') and hasattr(type(v), '__iter__'):
        if any(map(is_potential_path, v)):
          v.clear()
    except OSError:
      pass


def strip_paths_from_modules():
  for m in sys.modules.values():
    remove_potential_paths_from_object(m)
    for a in dir(m):
      try:
        remove_potential_paths_from_object(getattr(m,a))
      except AttributeError:
        # Remove the entire object if it contains any read-only paths
        setattr(m, a, None)


def clear_handles():
  sys.dllhandle = 0


def is_dunder(name):
  return name.startswith('__') and name.endswith('__')


def reset_platform_cache():
  for a in dir(platform):
    i = getattr(platform, a)
    if hasattr(i, 'clear') and not is_dunder(a):
      i.clear()
    elif 'cache' in a:
      setattr(platform, a, None)

def deelevate_user_id():
  if os.getuid() == 0:
    os.setuid(ARBITRARY_LARGE_ID)

def deelevate_group_id():
  if os.getgid() == 0:
    os.setgid(ARBITRARY_LARGE_ID)

DEFAULT_SAFEGUARDS = [clear_environment_variables]
ALL_SAFEGUARDS = [clear_handles, strip_paths_from_modules, reset_platform_cache] + DEFAULT_SAFEGUARDS

if platform.system() == 'Linux':
  DEFAULT_SAFEGUARDS.insert(0, enable_default_seccomp)
  ALL_SAFEGUARDS.insert(0, enable_strict_seccomp)

if platform.system() == 'FreeBSD':
  ALL_SAFEGUARDS.insert(0, enable_capsicum)

if hasattr(os, 'getuid'):
  DEFAULT_SAFEGUARDS.append(deelevate_user_id)
  ALL_SAFEGUARDS.append(deelevate_user_id)

if hasattr(os, 'getgid'):
  DEFAULT_SAFEGUARDS.append(deelevate_group_id)
  ALL_SAFEGUARDS.append(deelevate_group_id)


def enable_default_safeguards():
  for safeguard in DEFAULT_SAFEGUARDS:
    safeguard()


def enable_all_safeguards():
  for safeguard in ALL_SAFEGUARDS:
    safeguard()
