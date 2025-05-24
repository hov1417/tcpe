#!/usr/bin/env python3
import sys

arg = sys.argv.pop(1)

power = 1
ip = 0
for x in arg.split('.')[::-1]:
    ip += int(x) * power
    power *= 256

print(str(ip) + 'u')

