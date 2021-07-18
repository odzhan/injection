# test1.py
from capstone import *
import array

md = Cs(CS_ARCH_X86, CS_MODE_64)
cs = bytearray(b'\x00\x00')

def is_allowed(ch):
  if(ch >= 0x80 and ch <= 0x8C):
    return False
  if(ch >= 0x91 and ch <= 0x9C):
    return False
  if(ch == 0x8E or ch == 0x9E or ch == 0x9F):
    return False
  return True
  
for i in range(0, 256):
  if not is_allowed(i): 
    continue
  cs[0] = i
  for insn in md.disasm(cs, 0):
    if insn.size == 1:
      print(''.join('\\x{:02x}'.format(x) for x in insn.bytes), end='')
      print(" /* %s\t%s */" %(insn.mnemonic, insn.op_str))
