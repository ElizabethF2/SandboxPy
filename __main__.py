import os, sys
import . as sandboxpy

HELP = """
usage: SandboxPy [-h] [--id SANDBOX_ID] [--wr [WRITABLE_PATH ...]] [--ro [READ_ONLY_PATH ...]] -- [command [arg ...]]

SandboxPy

required arguments:
  --id SANDBOX_ID, -i SANDBOX_ID
                        Specify what the ID of the sandbox to use

optional arguments:
  -h, --help            show this help message and exit  
  --wr [WRITABLE_PATH ...], -w [WRITABLE_PATH ...]
                        Specify which paths the sandbox can write to
  --ro [READ_ONLY_PATH ...], -r [READ_ONLY_PATH ...]
                        Specify which paths the sandbox can read from
""".lstrip()

def show_help_and_die():
  print(HELP)
  sys.exit()

last_arg_state = None
cmd = []
id = None
writable_paths = []
readonly_paths = []

for arg in sys.argv[1:]:
  if last_arg_state == 'cmd':
    cmd.append(arg)
  elif last_arg_state == 'id':
    id = arg
    last_arg_state = None
  elif arg in ('--id', '-i'):
    last_arg_state = 'id'
  elif last_arg_state == 'wr':
    writable_paths.append(arg)
    last_arg_state = None
  elif arg in ('--wr', '-w'):
    last_arg_state = 'wr'
  elif last_arg_state == 'ro':
    readonly_paths.append(arg)
    last_arg_state = None
  elif arg in ('--ro', '-r'):
    last_arg_state = 'ro'
  elif arg == '--':
    last_arg_state = 'cmd'
  else:
    cmd.append(arg)
    last_arg_state = 'cmd'

if not id:
  show_help_and_die()

if not cmd:
  show_help_and_die()

proc = sandboxpy.run(cmd,
                     id,
                     readable_paths = readonly_paths,
                     writable_paths = writable_paths,
                     env = dict(os.environ),
                     cwd = os.getcwd())

# TODO: IO handling

sys.exit(proc.wait())
