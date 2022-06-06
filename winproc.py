import os, subprocess, msvcrt, signal, threading
from ctypes import *
from ctypes.wintypes import *

WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102
INFINITE = 0xFFFFFFFF
DUPLICATE_SAME_ACCESS = 0x00000002

kernel32 = windll.kernel32
DuplicateHandle = kernel32.DuplicateHandle
DuplicateHandle.argtypes = HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD

def dict_to_env_block(d):
  return create_unicode_buffer(''.join((k + '=' + v + '\0' for k,v in d.items())) + '\0')

def make_inheritable(handle):
  out = HANDLE()
  proc = kernel32.GetCurrentProcess()
  if not DuplicateHandle(proc, handle, proc, byref(out), 0, True, DUPLICATE_SAME_ACCESS):
    raise WinError()
  if not kernel32.CloseHandle(handle):
    raise WinError()
  return out

def create_pipe():
  hReadPipe = HANDLE()
  hWritePipe = HANDLE()
  if not kernel32.CreatePipe(byref(hReadPipe), byref(hWritePipe), 0, 0):
    raise WinError()
  return hReadPipe, hWritePipe

class SandboxedProcess(object):
  def __init__(self, args, stdin_handle, stdout_handle):
    self.args = args
    self.sandbox_proc = None
    self.returncode = None
    self.kill = self.terminate
    self._lock = threading.Lock()

    self._stdin_handle = stdin_handle
    self._stdout_handle = stdout_handle
    fd = msvcrt.open_osfhandle(stdin_handle.value, 0)
    self.stdin = open(fd, 'wb', -1)
    fd = msvcrt.open_osfhandle(stdout_handle.value, 0)
    self.stdout = open(fd, 'rb', -1)
    self.stderr = self.stdout

  def __del__(self):
    if not kernel32.CloseHandle(self.proc):
      raise WinError()

  def __repr__(self):
    r = '<SandboxedProcess: returncode: {} args: {}>'.format(self.returncode, self.args)
    if len(r) > 80:
      return r[:76] + '...>'
    return r

  def poll(self):
    if self.returncode is None:
      if kernel32.WaitForSingleObject(self.proc, 0) == WAIT_OBJECT_0:
        i = c_int(0)
        if not kernel32.GetExitCodeProcess(self.proc, byref(i)):
          raise WinError()
        self.returncode = i.value
    return self.returncode

  def wait(self, timeout=None):
    to = INFINITE if timeout is None else int(timeout*1000)
    res = kernel32.WaitForSingleObject(self.proc, to)
    if res == WAIT_OBJECT_0:
      return self.poll()
    elif res == WAIT_TIMEOUT:
      raise subprocess.TimeoutExpired(self.args, timeout)
    else:
      raise WinError()

  def terminate(self):
    if not kernel32.TerminateProcess(self.proc, 0):
      raise WinError()

  def send_signal(self, sig):
    if self.returncode is not None:
      return
    if sig == signal.SIGTERM:
      self.terminate()
    elif sig == signal.CTRL_C_EVENT:
      os.kill(self.proc, signal.CTRL_C_EVENT)
    elif sig == signal.CTRL_BREAK_EVENT:
      os.kill(self.proc, signal.CTRL_BREAK_EVENT)
    else:
      raise ValueError("Unsupported signal: {}".format(sig))

  def _read_worker(self, pipe, queue):
    while True:
      b = pipe.read()
      if not b:
        break
      queue.append(b)
    pipe.close()

  def communicate(self, input=None, timeout=None):
    with self._lock:
      if not hasattr(self, '_stdout_queue'):
        self._stdout_queue = []
        self._stdout_thread = threading.Thread(target=self._read_worker,
                                               args=(self.stdout, self._stdout_queue),
                                               daemon=True)
        self._stdout_thread.start()

    if self.stdin and input:
      stdin.write(input)

    self.wait(timeout)

    self._stdout_thread.join()
    stdout = ('' if hasattr(self.stdout, 'encoding') else b'').join(self._stdout_queue)
    return stdout, stdout
