import os, json, ctypes, hashlib, sys, shutil
from ctypes import wintypes
from . import wincontainer, winproc
from .winproc import SandboxedProcess
from . import util

MAX_APPCONTAINER_NAME = 50

data_path = os.path.expandvars('%LOCALAPPDATA%\\SandboxPy')
containers_path = os.path.join(data_path, 'containers.json')

kernel32 = ctypes.windll.kernel32

INFINITE = 0xFFFFFFFF
WAIT_FAILED = 0xFFFFFFFF

class WinCrossProcMutex(object, name = 'Sandbox_py_Global_Mutex'):
  def __enter__(self):
    handle = kernel32.CreateMutexW(0, False, name.encode())
    if not handle:
      raise ctypes.WinError()

    if kernel32.WaitForSingleObject(handle, INFINITE) == WAIT_FAILED:
      raise ctypes.WinError()

    self.handle = handle

  def __exit__(self, *args):
    if not kernel32.ReleaseMutex(self.handle):
      raise ctypes.WinError()
    if not kernel32.CloseHandle(self.handle):
      raise ctypes.WinError()

def generate_appcontainer_name(id):
  return ('sandbox_py_' + hashlib.sha1(id.encode()).hexdigest())[:MAX_APPCONTAINER_NAME]

def load_containers():
  try:
    with open(containers_path, 'r') as f:
      return json.load(f)
  except FileNotFoundError:
    return {}

def run(cmd, id, readable_paths=[], writable_paths=[], writable_paths_ensure_exists=[], env=None, cwd=None):
  with WinCrossProcMutex():
    containers = load_containers()
    old_container = containers.get(id)
    new_container = {
      'readable_paths': sorted(readable_paths),
      'writable_paths': sorted(writable_paths),
      'writable_paths_ensure_exists': sorted(writable_paths_ensure_exists),
    }

    container_name = generate_appcontainer_name(id)
    container = wincontainer.create_or_get_container(container_name)

    container_modified = False
    if old_container != new_container:
      container_modified = True

      wincontainer.delete_file_permission(container, wincontainer.get_container_folder_path(container))

      if old_container:
        for i in ('readable_paths', 'writable_paths'):
          for old_path in old_container[i]:
            if old_path not in new_container[i]:
              try:
                wincontainer.delete_file_permission(container, old_path)
              except FileNotFoundError:
                pass
      for i,f in (('readable_paths', 'add_read_file_permission'), ('writable_paths', 'add_write_file_permission')):
        for new_path in new_container[i]:
          if (not old_container or new_path not in old_container[i]) and os.path.exists(new_path):
            getattr(wincontainer, f)(container, new_path)
    dir_keep_alive_handles = []
    for new_path in new_container['writable_paths_ensure_exists']:
      try:
        os.mkdir(new_path)
        created = True
      except FileExistsError:
        created = False
      dir_keep_alive_handles.append(util.get_keep_alive_handle(new_path))
      different_from_old_container = not old_container or new_path not in old_container['writable_paths_ensure_exists']
      if different_from_old_container or created:
        wincontainer.add_write_file_permission(container, new_path)
        if different_from_old_container:
          container_modified = True

    if container_modified:
      containers[id] = new_container
      try:
        os.mkdir(data_path)
      except FileExistsError:
        pass
      with open(containers_path, 'w') as f:
        json.dump(containers, f)

    stdin_read, stdin_write = winproc.create_pipe()
    stdout_read, stdout_write = winproc.create_pipe()
    proc = SandboxedProcess(cmd, stdin_write, stdout_read)

    if env is not None:
      env = winproc.dict_to_env_block(env)

    stdin_read = winproc.make_inheritable(stdin_read)
    stdout_write = winproc.make_inheritable(stdout_write)

    pi = wincontainer.execute(container, cmd, env=env, cwd=cwd, stdin=stdin_read, stdout=stdout_write)
    proc.pid = pi.dwProcessId
    proc.proc = pi.hProcess
    proc.dir_keep_alive_handles = dir_keep_alive_handles

    return proc


def get_python_paths():
  return [os.path.dirname(sys.executable)]


def delete_container(id, container):
  container_name = generate_appcontainer_name(id)
  con = wincontainer.create_or_get_container(container_name)
  for i in ('readable_paths', 'writable_paths', 'writable_paths_ensure_exists'):
    for path in container[i]:
      try:
        wincontainer.delete_file_permission(con, path)
      except FileNotFoundError:
        pass
  wincontainer.delete_container(container_name)


def delete_all_sandboxes():
  with WinCrossProcMutex():  
    for id, container in load_containers().items():
      delete_container(id, container)
    os.remove(containers_path)
    os.rmdir(data_path)
