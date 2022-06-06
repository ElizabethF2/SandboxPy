from ctypes import *
from ctypes.wintypes import *

PSID = HANDLE
PSID_AND_ATTRIBUTES = PSID
PACL = HANDLE

ERROR_ALREADY_EXISTS_AS_HRESULT = -2147024713
ERROR_SUCCESS = 0

GRANT_ACCESS = 1
NO_MULTIPLE_TRUSTEE = 0
TRUSTEE_IS_SID = 0
TRUSTEE_IS_GROUP = 2
SE_FILE_OBJECT = 1
DACL_SECURITY_INFORMATION = 4
OBJECT_INHERIT_ACE = 1
CONTAINER_INHERIT_ACE = 2
AclSizeInformation = 2

READ_CONTROL = 0x20000
FILE_LIST_DIRECTORY = 0x1
FILE_TRAVERSE = 0x20
FILE_READ_ATTRIBUTES = 0x80
FILE_READ_EA = 0x8
FILE_EXECUTE = 0x20
SYNCHRONIZE = 0x100000
STANDARD_RIGHTS_READ = READ_CONTROL
STANDARD_RIGHTS_EXECUTE = READ_CONTROL
STANDARD_RIGHTS_REQUIRED = 0xF0000

FILE_GENERIC_READ = STANDARD_RIGHTS_READ | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE
FILE_GENERIC_EXECUTE = STANDARD_RIGHTS_EXECUTE | FILE_READ_ATTRIBUTES | FILE_EXECUTE | SYNCHRONIZE
FILE_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF

READ_FLAGS = FILE_GENERIC_READ | FILE_TRAVERSE | FILE_GENERIC_EXECUTE

PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 131081
CREATE_UNICODE_ENVIRONMENT = 0x400
EXTENDED_STARTUPINFO_PRESENT = 0x80000
STARTF_USESTDHANDLES = 0x100

class TRUSTEE(Structure):
  _fields_ = [('pMultipleTrustee', HANDLE),
              ('MultipleTrusteeOperation', c_uint),
              ('TrusteeForm', c_uint),
              ('TrusteeType', c_uint),
              ('ptstrName', PSID)]     # Despite its name, this field will accept a SID if TrusteeForm is TRUSTEE_IS_SID

class EXPLICIT_ACCESS(Structure):
  _fields_ = [('grfAccessPermissions', DWORD),
              ('grfAccessMode', c_uint),
              ('grfInheritance', DWORD),
              ('Trustee', TRUSTEE)]

class ACL_SIZE_INFORMATION(Structure):
  _fields_ = [('AceCount', DWORD),
              ('AclBytesInUse', DWORD),
              ('AclBytesFree', DWORD)]

class ACE_HEADER(Structure):
  _fields_ = [('AceType', BYTE),
              ('AceFlags', BYTE),
              ('AceSize', WORD)]

class ACCESS_ALLOWED_ACE(Structure):
  _fields_ = [('Header', ACE_HEADER),
              ('Mask', DWORD),
              ('SidStart', DWORD)]

PACE = POINTER(ACCESS_ALLOWED_ACE)
SidStart_offset = sizeof(ACE_HEADER) + sizeof(DWORD)

class SECURITY_CAPABILITIES(Structure):
  _fields_ = [('AppContainerSid', PSID),
              ('Capabilities', PSID_AND_ATTRIBUTES),
              ('CapabilityCount', DWORD),
              ('Reserved', DWORD)]

class STARTUPINFO(Structure):
  _fields_ = [('cb', DWORD),
              ('lpReserved', LPSTR),
              ('lpDesktop', LPSTR),
              ('lpTitle', LPSTR),
              ('dwX', DWORD),
              ('dwY', DWORD),
              ('dwXSize', DWORD),
              ('dwYSize', DWORD),
              ('dwXCountChars', DWORD),
              ('dwYCountChars', DWORD),
              ('dwFillAttribute', DWORD),
              ('dwFlags', DWORD),
              ('wShowWindow', WORD),
              ('cbReserved2', WORD),
              ('lpReserved2', LPBYTE),
              ('hStdInput', HANDLE),
              ('hStdOutput', HANDLE),
              ('hStdError', HANDLE)]

LPPROC_THREAD_ATTRIBUTE_LIST = HANDLE

class STARTUPINFOEX(Structure):
  _fields_ = [('StartupInfo', STARTUPINFO),
              ('lpAttributeList', LPPROC_THREAD_ATTRIBUTE_LIST)]

lpAttributeList_offset = sizeof(STARTUPINFO)

class PROCESS_INFORMATION(Structure):
  _fields_ = [('hProcess', HANDLE),
              ('hThread', HANDLE),
              ('dwProcessId', DWORD),
              ('dwThreadId', DWORD)]

class Container(object):
  def __init__(self, name):
    self.name = name
    self.psid = PSID()

  def __del__(self):
    if self.psid.value and windll.advapi32.FreeSid(self.psid):
      raise WinError()

def create_or_get_container(name):
  container = Container(name)
  wname = create_unicode_buffer(name)
  hr = windll.userenv.CreateAppContainerProfile(wname, wname, wname, 0, 0, byref(container.psid))
  if hr == ERROR_ALREADY_EXISTS_AS_HRESULT:
    hr = windll.userenv.DeriveAppContainerSidFromAppContainerName(wname, byref(container.psid))
    if hr < 0:
      raise OSError(None, 'retrieving existing container', name, hr)
  elif hr < 0:
    raise OSError(None, 'creating container', name, hr)
  return container

def delete_container(name):
  wname = create_unicode_buffer(name)
  hr = windll.userenv.DeleteAppContainerProfile(wname)
  if hr < 0:
    raise OSError(None, 'deleting container', name, hr)

def add_file_permissions(container, path, permissions):
  wpath = create_unicode_buffer(path)
  oldAcl, newAcl = PACL(), PACL()

  access = EXPLICIT_ACCESS()
  access.grfAccessMode = GRANT_ACCESS
  access.grfAccessPermissions = permissions
  access.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
  access.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE
  access.Trustee.pMultipleTrustee = None
  access.Trustee.ptstrName = container.psid
  access.Trustee.TrusteeForm = TRUSTEE_IS_SID
  access.Trustee.TrusteeType = TRUSTEE_IS_GROUP

  e = windll.advapi32.GetNamedSecurityInfoW(wpath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, 0, 0, byref(oldAcl), 0, 0)
  if e != ERROR_SUCCESS:
    raise OSError(None, 'getting security info', path, e)

  try:
    e = windll.advapi32.SetEntriesInAclW(1, byref(access), oldAcl, byref(newAcl))
    if e != ERROR_SUCCESS:
      raise OSError(None, 'set acl entries', path, e)

    e = windll.advapi32.SetNamedSecurityInfoW(wpath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, 0, 0, newAcl, 0)
    if e != ERROR_SUCCESS:
      raise OSError(None, 'set info', path, e)
  finally:
    if newAcl.value is not None and windll.kernel32.LocalFree(newAcl):
      raise WinError()

def add_read_file_permission(container, path):
  add_file_permissions(container, path, READ_FLAGS)

def add_write_file_permission(container, path):
  add_file_permissions(container, path, FILE_ALL_ACCESS)

def delete_file_permission(container, path):
  wpath = create_unicode_buffer(path)
  acl = PACL()
  
  e = windll.advapi32.GetNamedSecurityInfoW(wpath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, 0, 0, byref(acl), 0, 0)
  if e != ERROR_SUCCESS:
    raise OSError(None, 'getting acl for delete', path, e)

  size_info = ACL_SIZE_INFORMATION()
  if not windll.advapi32.GetAclInformation(acl, byref(size_info), sizeof(size_info), AclSizeInformation):
    raise OSError(None, 'getting acl info for delete', path, GetLastError())

  count = size_info.AceCount
  ace_index = 0
  ace = PACE()
  while ace_index < count:
    if not windll.advapi32.GetAce(acl, ace_index, byref(ace)):
      raise OSError(None, 'getting ace', path, GetLastError())

    if windll.advapi32.EqualSid(container.psid, byref(ace.contents, SidStart_offset)):
      if not windll.advapi32.DeleteAce(acl, ace_index):
        raise OSError(None, 'deleting ace', path, GetLastError())
      count -= 1
    else:
      ace_index += 1

  e = windll.advapi32.SetNamedSecurityInfoW(wpath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, 0, 0, acl, 0)
  if e != ERROR_SUCCESS:
    raise OSError(None, 'set info for delete', path, GetLastError())

def execute(container, cmd, cwd=None, env=None, stdin=None, stdout=None):
  sc = SECURITY_CAPABILITIES()
  sc.AppContainerSid = container.psid

  si = STARTUPINFOEX()
  si.StartupInfo.cb = sizeof(si)
  size = c_ulong()
  windll.kernel32.InitializeProcThreadAttributeList(0, 1, 0, byref(size))
  attribute_list = (BYTE * size.value)()
  si.lpAttributeList = cast(attribute_list, c_void_p)

  try:
    if not windll.kernel32.InitializeProcThreadAttributeList(byref(attribute_list), 1, 0, byref(size)):
      raise OSError(None, 'init attribute list', cmd, GetLastError())
    if not windll.kernel32.UpdateProcThreadAttribute(byref(attribute_list), 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, byref(sc), sizeof(sc), 0, 0):
      raise OSError(None, 'updating attributes', cmd, GetLastError())

    name = create_unicode_buffer(cmd[0])
    cmd_line = create_unicode_buffer(' '.join(('"' + i.replace('"', '""') + '"' for i in cmd)))

    pi = PROCESS_INFORMATION()
    flags = CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT
    if stdin is not None and stdout is not None:
      si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES
      si.StartupInfo.hStdInput = stdin
      si.StartupInfo.hStdOutput = stdout
      si.StartupInfo.hStdError = stdout
    if not windll.kernel32.CreateProcessW(name, cmd_line, 0, 0, True, flags, env, cwd, byref(si), byref(pi)):
      raise OSError(None, 'creating process', cmd, GetLastError())
  finally:
    if not windll.kernel32.DeleteProcThreadAttributeList(byref(attribute_list)):
      raise OSError(None, 'deleting attribute list', cmd, GetLastError())
    if stdin is not None:
      if not windll.kernel32.CloseHandle(stdin):
        raise WinError()
    if stdout is not None:
      if not windll.kernel32.CloseHandle(stdout):
        raise WinError()
  return pi

def sid_to_string(sid):
  out = c_void_p()
  try:
    if not windll.advapi32.ConvertSidToStringSidW(sid, byref(out)):
      raise WinError()
    s = wstring_at(out)
  finally:
    if out.value is not None and windll.kernel32.LocalFree(out):
      raise WinError()
  return s

def get_container_folder_path(container):
  sid = sid_to_string(container.psid)
  out = c_void_p()
  try:
    hr = windll.userenv.GetAppContainerFolderPath(sid, byref(out))
    if hr != ERROR_SUCCESS:
      raise OSError(None, 'getting container folder path', None, hr)
    s = wstring_at(out)
  finally:
    if out.value is not None and windll.kernel32.LocalFree(out):
      raise WinError()
  return s
