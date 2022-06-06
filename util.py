import os, tempfile

def path_contains_or_is_in_path(allowed_path, path_being_tested):
  allowed_path = os.path.abspath(allowed_path)
  path_being_tested = os.path.abspath(path_being_tested)
  allowed_path = allowed_path.split(os.path.sep)
  path_being_tested = path_being_tested.split(os.path.sep)
  return path_being_tested[:len(allowed_path)] == allowed_path

def add_path_if_unique(paths, new_path):
  if not any(map(lambda i: path_contains_or_is_in_path(i, new_path), paths)):
    paths.append(new_path)

def get_keep_alive_handle(path):
  return tempfile.NamedTemporaryFile(prefix='sandbox_dir_keep_alive_', dir=path)

def ensure_dir_exists_and_get_keep_alive_handle(path):
  try: os.mkdir(path)
  except FileExistsError: pass
  return get_keep_alive_handle(path)
