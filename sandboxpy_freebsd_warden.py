TMP_DIR = '/tmp'
PROXY_DIRS = ['/usr/jails']

# If necessary, the two lines above can be changed to different locations
# Do not edit any of the lines below

import sys, os, stat, subprocess, json, time, re, math

def get_prefix():
  return 'sandbox_py_jail_' + os.environ.get('SUDO_USER') + '_'

def common_start(path1, path2):
  common = ''
  if not path1.endswith(os.path.sep):
    path1 += os.path.sep
  if not path2.endswith(os.path.sep):
    path2 += os.path.sep
  for i in range(min(len(path1), len(path2))):
    if path1[i] == path2[i]:
      common += path1[i]
    else:
      break
  return common

def get_proxy_root(path):
  dir = sorted([(i, common_start(i,path).count(os.path.sep)) for i in PROXY_DIRS], key=lambda i: i[1])[-1][0]
  return os.path.join(dir, '.sandbox_py_proxies')

class BSDCrossProcMutex(object):
  def __enter__(self):
    self.path = os.path.join(TMP_DIR, '.sandbox_py_lockfile')
    self.fd = os.open(self.path, os.O_CREAT | os.O_EXLOCK)

  def __exit__(self, *args):
    os.close(self.fd)
    os.remove(self.path)

def get_mounts_for_container(jail_root):
  paths = []
  if not jail_root.endswith(os.path.sep):
    jail_root += os.path.sep
  out = subprocess.check_output(['mount'])
  for line in (out if type(out) is str else out.decode()).splitlines():
    idxs = [m.start()+4 for m in re.finditer(' on ', line)]
    path = line[idxs[math.floor(len(idxs)/2)]:line.rindex(' (')].strip()
    if path.startswith(jail_root):
      paths.append(path)
  return paths

def delete_all_sandboxes():
  import shutil
  prefix = get_prefix()
  with BSDCrossProcMutex():
    for name in filter(lambda i: i.startswith(prefix), os.listdir(TMP_DIR)):
      jail_root = os.path.join(TMP_DIR, name)
      for path in get_mounts_for_container(jail_root):
        subprocess.check_output(['umount', path])
      shutil.rmtree(jail_root)
    for root in PROXY_DIRS:
      try:
        shutil.rmtree(os.path.join(root, '.sandbox_py_proxies'))
      except FileNotFoundError:
        pass

def verify_user_can_access_path(path, readonly):
  if not os.path.exists(path):
    raise FileNotFoundError(path)
  arg = '-r' if readonly else '-w'
  epath = path.replace(' ', '\\ ')
  user = os.environ.get('SUDO_USER')
  subprocess.check_output(['su', '-c', "'test " + arg + " " + epath + "'", "-", user])

def mount_or_link(jail_root, path, readonly):
  verify_user_can_access_path(path, readonly)
  dest = os.path.join(jail_root, path[1:])
  if os.path.isdir(path):
    if not os.path.ismount(dest):
      try:
        os.makedirs(dest)
      except FileExistsError:
        pass
      if readonly:
        subprocess.check_output(['mount_nullfs', '-o', 'ro', path, dest])
      else:
        subprocess.check_output(['mount_nullfs', path, dest])
    return dest
  else:
    # Since files can't be mounted directly, a proxy directory is created in a path
    # that's likely to be on the same device as the file so a hard link can be created
    # to the actual file. The proxy is then mounted in the sandbox.
    try:
      os.makedirs(os.path.dirname(dest))
    except FileExistsError:
      pass
    proxy_path = os.path.join(get_proxy_root(path), dest[1:])
    try:
      os.makedirs(os.path.dirname(proxy_path))
    except FileExistsError:
      pass
    try:
      os.link(path, proxy_path)
    except FileExistsError:
      pass
    except OSError as error:
      if error.errno != 18: # EXDEV, cross-device link error
        raise error
    if not os.path.ismount(os.path.dirname(dest)):
      if readonly:
        subprocess.check_output(['mount_nullfs', '-o', 'ro', os.path.dirname(proxy_path), os.path.dirname(dest)])
      else:
        subprocess.check_output(['mount_nullfs', os.path.dirname(proxy_path), os.path.dirname(dest)])
    return os.path.dirname(dest)

def main():
  payload = json.loads(input())
  if payload == 'delete_all_sandboxes':
    return delete_all_sandboxes()

  sandbox_name = get_prefix() + payload['id']
  assert(len(sandbox_name) > 0)
  assert(not any((i in sandbox_name for i in (os.path.pardir, os.path.sep))))
  jail_root = os.path.join(TMP_DIR, sandbox_name)
  mounts = set()

  with BSDCrossProcMutex():
    # Create the sandbox if it doesn't already exist
    try:
      os.mkdir(jail_root)
    except FileExistsError:
      pass

    # Add readable paths
    for path in payload['readable_paths']:
      mounts.add(mount_or_link(jail_root, path, True))

    # Add writable paths
    for path in payload['writable_paths']:
      mounts.add(mount_or_link(jail_root, path, False))

    # Remove any already mounted paths from prior calls that should no longer be mounted
    for path in get_mounts_for_container(jail_root):
      if path not in mounts:
        subprocess.check_output(['umount', path])
        os.rmdir(path)

    #  Run the command in the sandbox
    cmd = payload['cmd']
    proc = subprocess.Popen(['quickjail', 'path='+jail_root, 'command='+cmd[0]] + cmd[1:])

  # Wait for the process to exit and forward the return code to the caller
  sys.exit(proc.wait())

if __name__ == '__main__':
  main()
