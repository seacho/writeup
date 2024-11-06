IMM a = 0x2f
STK N a

IMM a = 0x66
STK N a

IMM a = 0x6c
STK N a

IMM a = 0x61
STK N a

IMM a = 0x67
STK N a

IMM a = 0x00
STK N a

IMM a = 0x01
IMM b = 0x0
IMM c = 0x0
SYS open a


IMM c = 0xff
SYS read_memory c

IMM c = 0xff
IMM a = 0x1
IMM b = 0x0
SYS write a
SYS exit a