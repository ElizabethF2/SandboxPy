import sys, os, tempfile
import sandbox.util as util

class SandboxedProcess(subprocess.Popen):
  pass

def _fix_path(path):
  if not path.endswith(os.path.sep) and os.path.isdir(path):
    path += os.path.sep
  elif os.path.isfile(path):
    path += '$'
  return path.replace('"', '\\"')

def run(cmd, id, readable_paths=[], writable_paths=[], writable_paths_ensure_exists=[], env=None, cwd=None):
  profile = '(version 1)\n(deny default)'
  profile += '(allow file-write* file-read-data file-read-metadata process-exec'
  for path in readable_paths:
    profile += '(regex "^' + _fix_path(path) + '")'
  profile += ')(allow file-read-data file-read-metadata process-exec '
  for path in writable_paths:
    profile += '(regex "^' + _fix_path(path) + '")'
  dir_keep_alive_handles = []
  for path in writable_paths_ensure_exists:
    dir_keep_alive_handles.append(util.ensure_dir_exists_and_get_keep_alive_handle(path))
    profile += '(regex "^' + _fix_path(path) + '")'
  profile += ')'
  scmd = ['sandbox-exec', '-p', profile]
  proc = SandboxedProcess(
           scmd + cmd,
           stdin = subprocess.PIPE,
           stdout = subprocess.PIPE,
           stderr = subprocess.PIPE,
           env=env,
           cwd=cwd,
         )
  proc.dir_keep_alive_handles = dir_keep_alive_handles
  return proc

def get_python_paths():
  paths = []
  for path in [os.path.dirname(sys.executable), os.path.dirname(os.__file__)]:
    util.add_path_if_unique(paths, path)
  return paths
