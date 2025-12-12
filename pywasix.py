import pywasm
import warnings

def run(cmd, **kwargs):
  warnings.warn('pywasm support is incomplete and will likely not work')
  # TODO implement and import wasix functions w/ path and network filtering
  runtime = pywasm.core.Runtime()
  module = runtime.instance_from_file(cmd[0])
  return runtime.invocate(module, '_start', [])
