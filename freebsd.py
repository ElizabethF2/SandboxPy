import sys, os, subprocess, json, glob, tempfile
import sandbox.util as util

class SandboxedProcess(subprocess.Popen):
  pass

def _send_payload_to_warden(payload, env=None, cwd=None, check_return_code=False):
  proc = SandboxedProcess(
           ['sudo', sys.executable, '-I', '-m', 'sandboxpy_freebsd_warden'],
           stdin = subprocess.PIPE,
           stdout = subprocess.PIPE,
           stderr = subprocess.PIPE,
           env=env,
           cwd=cwd,
         )
  proc.stdin.write(payload if hasattr(proc.stdin, 'encoding') else payload.encode())
  proc.stdin.flush()
  if check_return_code:
    out = proc.communicate()
    rc = proc.poll()
    if rc != 0:
      raise OSError(rc, out)
  return proc

def run(cmd, id, readable_paths=[], writable_paths=[], writable_paths_ensure_exists=[], env=None, cwd=None):
  payload = json.dumps({
    'cmd': cmd,
    'id': id,
    'readable_paths': readable_paths,
    'writable_paths': writable_paths + writable_paths_ensure_exists,
    'env': dict(os.environ if env is None else env),
    'cwd': cwd,
  }) + '\n'
  dir_keep_alive_handles = []
  for path in writable_paths_ensure_exists:
    dir_keep_alive_handles.append(util.ensure_dir_exists_and_get_keep_alive_handle(path))
  proc = _send_payload_to_warden(payload)
  proc.dir_keep_alive_handles = dir_keep_alive_handles
  return proc

def delete_all_sandboxes():
  payload = '"delete_all_sandboxes"\n'
  _send_payload_to_warden(payload, check_return_code=True)

def get_python_paths():
  paths = ['/libexec', '/usr/lib', '/usr/local/bin', '/usr/local/lib', '/lib']
  for path in glob.iglob('/var/run/ld-elf*.hints'):
    util.add_path_if_unique(paths, path)
  for path in [os.path.dirname(sys.executable), os.path.dirname(os.__file__)]:
    util.add_path_if_unique(paths, path)
  return paths
