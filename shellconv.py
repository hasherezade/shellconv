#!/usr/bin/env python
"""shellconv.py: Fetches shellcode (in typical format) from a file and converts it into assembly with the help of objdump."""

__author__ = 'hasherezade (hasherezade.net)'
__license__ = "GPL"

import os
import sys
import re
import subprocess
import binascii
import colorterm

HEX_NUM = '[0-9a-f-A-F]'
SHELC_CHUNK = r'\\x' + HEX_NUM + '{2}'
DISASM_LINE = r'\s?[0-9a-f]*:\s[0-9a-f]{2}\s[0-9a-f]{2}\s*\w*\s.*'
IMM_DWORD = HEX_NUM + '{8}'

ARG_INFILE = 1
ARG_ARCH = 2
ARG_OUTFILE = 3

ARG_MIN = ARG_INFILE + 1

def get_chunks(buf):
    t = re.findall (SHELC_CHUNK, buf)
    byte_buf = []
    for chunk in t:
        x = chunk[2:]
        num = int (x, 16)
        byte_buf.append(num)
    return byte_buf


def has_keyword(line, keywords):
    for key in keywords:
        if key in line:
            return True
    return False

def chunkstring(string, chunk_len):
    return (string[0+i:chunk_len+i] for i in range(0, len(string), chunk_len))

def dwordstr_to_str(imm_str):
    chunks = list(chunkstring(imm_str, 2))
    chars = []
    for c in chunks:
        chars.append(binascii.unhexlify(c))
    return "".join(chars)

def fetch_imm(line):
    val = re.findall(IMM_DWORD, line)
    if len(val) > 0:
        imm_str = dwordstr_to_str(val[0])
        return imm_str + " -> \"" + imm_str[::-1]+"\""

def color_disasm_print(disasm_lines):
    for line in disasm_lines:
        imm = fetch_imm(line)
        if (imm):
            line += " -> " + imm

        if has_keyword(line, ['push']):
            colorterm.color_msg(colorterm.GREEN, line)
        elif has_keyword(line,['int']):
            colorterm.color_msg(colorterm.RED, line)
        else:
            colorterm.color_msg(colorterm.BLUE, line)
    return

def process_out(out):
    t = re.findall(DISASM_LINE, out)
    lines = []
    for chunk in t:
        lines.append(chunk)
    return lines

def disasm(fileName, arch):
    print fileName
    print arch
    process_data = ['objdump', '-D', '-b','binary','-m', arch, '-M','intel', fileName]
    p = subprocess.Popen(process_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    if err:
        colorterm.err("Error: " + err)
        return
    colorterm.info("OK!")
    lines = process_out(out)
    color_disasm_print(lines)

def main():
    argc = sys.argv.__len__()
    argv = sys.argv
    arch = "i386"

    if (argc < ARG_MIN):
        print "Use: "+argv[0] + " " + "<inFile> <arch:optional> <outFile:optional>"
        print "arch: defined as in objdump -m, default: " + arch
        exit(-1)

    in_fileName = argv[ARG_INFILE]
    arch = "i386"
    if (argc > ARG_ARCH):
        arch = argv[ARG_ARCH]
    else:
        print "Default arch: " + arch

    out_fileName = "out.tmp"
    if (argc > ARG_OUTFILE):
        out_fileName = argv[ARG_OUTFILE]
    else:
        print "Default output (binary): " + out_fileName

    with open(in_fileName, "r") as fileIn:
        buf = fileIn.read()
        byte_buf = get_chunks(buf)

    print "---"
    print "Length (in bytes) = " + str(len(byte_buf))

    byte_arr = bytearray(byte_buf)
    with open(out_fileName, "wb") as fileOut:
        fileOut.write(byte_arr)
    disasm(out_fileName, arch)

if __name__ == "__main__":
    sys.exit(main())

