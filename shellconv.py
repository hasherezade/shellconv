#!/usr/bin/env python3
"""shellconv.py: Fetches shellcode (in typical format) from a file, disassemble it with the help of objdump
and prettyprint.
"""

__author__ = 'hasherezade (hasherezade.net)'
__license__ = "GPL"

import os
import sys
import re
import subprocess
import binascii
import termcolor
import argparse

HEX_BYTE = r'[0-9a-fA-F]{2}\s'
SHELC_CHUNK = r'\\x[0-9a-fA-F]{2}'
DISASM_LINE = r'\s?[0-9a-f]*:\s[0-9a-f]{2}.*'
IMM_DWORD = r'[0-9a-fA-F]{8}'
DISASM_LINENUM = r'^\s+[0-9a-f]+:\s+'
DISASM_BYTES = r':\s+([0-9a-f]{2}\s+)+'

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
    my_str = ""
    for c in chunks:
        val = binascii.unhexlify(c)
        my_str += val.decode()
    return my_str

def fetch_imm(line):
    vals = re.findall(IMM_DWORD, line)
    imm_strs = []
    for val in vals:
        imm_strs.append(dwordstr_to_str(val))
    if not imm_strs:
       return
    rev_strs = []
    for val in imm_strs:
        rev_strs.append(val[::-1])
    return "".join(imm_strs) + "-> \"" + "".join(rev_strs)+"\""

def is_printable(num):
    return (num >= 0x20 and num < 0x7f)

def append_ascii(line):
    m = re.search(DISASM_BYTES, line)
    if not m:
        return
    m_lnum = re.search(DISASM_LINENUM, line)
    if not m_lnum:
        return
    lnum_str = m_lnum.group(0)
    line = line[len(lnum_str):]

    bytes_str = m.group(0)
    t = re.findall(HEX_BYTE, bytes_str)
    ascii_line = []
    for bytestr in t:
        num = int (bytestr, 16)
        if (is_printable(num)):
            ascii_line.append(chr(num))
        else:
            ascii_line.append('.')
    return lnum_str + "".join(ascii_line) + "\t" + line

def color_disasm_print(disasm_lines):
    for orig_line in disasm_lines:
        line = append_ascii(orig_line)
        imm = fetch_imm(line)
        if (imm):
            line += " -> " + imm

        if has_keyword(orig_line, ['push']):
            print(termcolor.colored(line,'green'))
        elif has_keyword(orig_line, ['call','jmp']):
            print(termcolor.colored(line,'yellow'))
        elif has_keyword(orig_line, ['jn']):
            print(termcolor.colored(line,'purple'))
        elif has_keyword(orig_line, ['j']):
            print(termcolor.colored(line,'cyan'))
        elif has_keyword(orig_line,['int']):
            print(termcolor.colored(line,'magenta', attrs=['bold']))
        elif has_keyword(orig_line,['nop']):
            print(termcolor.colored(line,'grey'))
        elif has_keyword(orig_line,['bad']):
            print(termcolor.colored(line,'white','on_red'))
        else:
            print(termcolor.colored(line,'blue'))
    return

def process_out(out):
    t = re.findall(DISASM_LINE, out.decode('utf-8'))
    lines = []
    for chunk in t:
        lines.append(chunk)
    return lines

def disasm(fileName, arch):
    print(fileName)
    print(arch)
    process_data = ['objdump', '-D', '-b','binary','-m', arch, '-M','intel', fileName]
    p = subprocess.Popen(process_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    if err:
        print(termcolor.colored("Error:",'red', attrs=['underline']) + " " + err.decode('utf-8'))
        return
    print("OK!")
    lines = process_out(out)
    color_disasm_print(lines)

def print_charset(chunks):
    charset = set()
    for chunk in chunks:
        charset.add(chunk)
    print("Charset (unique = " + str(len(charset)) + "):")
    charset = sorted(charset)
    for char in charset:
        print('%02x'%(char), end=' ')
    print("\n---")

def main():
    # parse input arguments:
    parser = argparse.ArgumentParser(prog='shellconv.py', description="Shellconv: small tool for disassembling shellcode (using objdump)")
    parser.add_argument('--infile', dest="infile", default=None, help="The shellcode to be converted", required=True)
    parser.add_argument('--arch', dest="arch", default="i386", help="The architecture to be used (options: as in objdump -m)", required=False)
    parser.add_argument('--outfile', dest="outfile", default="out.tmp", help="Output file", required=False)
    args = parser.parse_args()
    
    if sys.platform == 'win32':
        os.system('color') #init colors
    
    arch = args.arch
    in_fileName = args.infile
    out_fileName = args.outfile

    with open(in_fileName, "r") as fileIn:
        buf = fileIn.read()
        byte_buf = get_chunks(buf)

    print("---")
    print("Length (in bytes) = " + str(len(byte_buf)))
    print_charset(byte_buf)

    byte_arr = bytearray(byte_buf)
    with open(out_fileName, "wb") as fileOut:
        fileOut.write(byte_arr)
    disasm(out_fileName, arch)

if __name__ == "__main__":
    sys.exit(main())


