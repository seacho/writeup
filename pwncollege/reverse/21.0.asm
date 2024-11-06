IMM d = 0x2f
IMM c = 0x80
STM *c = d

IMM d = 0x66
IMM c = 0x81
STM *c = d

IMM d = 0x6c
IMM c = 0x82
STM *c = d

IMM d = 0x61
IMM c = 0x83
STM *c = d

IMM d = 0x67
IMM c = 0x84
STM *c = d

IMM d = 0x0
IMM c = 0x85
STM *c = d
IMM a = 0x80
IMM b = 0x0
SYS open a

IMM b = 0x0
ADD b s
IMM c = 0xff

ADD a d
SYS read_memory d

IMM b = 0x0
ADD b s
IMM c = 0xff
ADD c d
IMM a = 0x1
SYS write d