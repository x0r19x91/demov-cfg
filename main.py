#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    CFG for main() in a movfuscated binary
"""

import capstone
import capstone.x86_const
import lief
import sys
import argparse

def error(msg):
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()
    exit()

def main():
    info = """
    -=-=-=[ Generate Control Flow Graph for main() in Movfuscated binaries ]=-=-=-
    Author: x0r19x91
    """
    
    parser = argparse.ArgumentParser(description=info)
    parser.add_argument('binary', help='Input file (32-bit movfuscated binary)')
    parser.add_argument('-o', '--output', help='Output file (dot)', default='graph.dot')

    args = parser.parse_args()

    path = args.binary
    elf = lief.parse(path)
    if not elf:
        error("Only ELF-32 bit files are supported!")

    if elf.header.identity_class.CLASS32 != elf.header.identity_class:
        error("Only ELF-32 bit files are supported!")

    seg = [x for y in elf.sections for x in y.segments]
    if len(seg) == 0:
        error("Must have atleast one segment!")

    entry = None
    for i in seg:
        if elf.entrypoint >= i.virtual_address and \
                elf.entrypoint < i.virtual_address+i.virtual_size:
            entry = i
            break

    if not entry:
        error("Invalid EntryPoint!")

    try:
        TARGET = elf.get_symbol('target').value
        BRANCH_TEMP = elf.get_symbol('branch_temp').value
        STACK_TEMP = elf.get_symbol('stack_temp').value
    except:
        error("Sorry only non-stripped Movfuscated Binaries are supported!")

    off = elf.entrypoint-entry.virtual_address
    raw_data = bytes(entry.content[off:])
    cs = capstone.Cs(mode=capstone.CS_MODE_32, arch=capstone.CS_ARCH_X86)
    cs.detail = 1
    g = {}
    target = 0
    stack_temp = []
    current = elf.entrypoint
    regs = {'eax': 0, 'ebx': 0, 'ecx': 0, 'edx': 0}
    last_assigned = None

    state = 0
    for i in cs.disasm(raw_data, elf.entrypoint):
        if i.mnemonic != 'mov':
            continue

        dst = i.operands[0]
        src = i.operands[1]

        if dst.type == capstone.x86_const.X86_OP_MEM and src.type == capstone.x86_const.X86_OP_REG:
            # mov branch_temp, eax
            if dst.mem.disp == BRANCH_TEMP:
                target = regs[i.reg_name(src.reg)]
                if i.reg_name(src.reg) == last_assigned:
                    target ^= 0x80000000
                    if ('%08x' % current) not in g:
                        g['%08x' % current] = []
                    g['%08x' % current].append('%08x' % target)
            elif dst.mem.disp == STACK_TEMP:
                t = regs[i.reg_name(src.reg)]
                if t & 0x80000000:
                    stack_temp.append('%08x' % t)
        elif dst.type == capstone.x86_const.X86_OP_REG:
            dname = i.reg_name(dst.reg)
            if src.type == capstone.x86_const.X86_OP_IMM:
                if src.imm & 0x80000000:
                    regs[dname] = src.imm
                    last_assigned = dname
            elif src.type == capstone.x86_const.X86_OP_MEM:
                if src.mem.disp == TARGET:
                    # mov eax, TARGET
                    current = i.address
                    if current & 0x80000000:
                        current ^= 0x80000000
                    if ('%08x' % current) not in g:
                        g['%08x' % current] = []


    dot = ['digraph cfg {']
    keys = sorted((int(i, 16) for i in g.keys()))

    main = int(g['%08x' % elf.entrypoint][0], 16)
    dot.append('entry -> _%08x;' % main)
    last = main
    keys = [i for i in keys if i > main]
    nodes = {'entry', '_%08x' % main}
    for i in keys:
        k = '%08x' % i
        for child in g[k]:
            dot.append('_%s -> _%s;' % (k, child))
            nodes.add("_"+k)
            nodes.add("_"+child)
    l = keys[-1]
    for i in keys:
        old = i
        if i == l:
            i = 'exit'
        else:
            i = '_%08x' % i
        nodes.add('_%08x' % last)
        nodes.add(i)
        dot.append('_%08x -> %s;' % (last, i))
        last = old

    for node in nodes:
        label = node
        if label[0] == '_':
            label = label[1:]
        dot.append('%s [shape="box", label="%s"];' % (node, label))

    dot.append('}')

    with open(args.output, "w") as handle:
        handle.write("\n".join(dot))

if __name__ == '__main__':
    main()
