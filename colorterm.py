#!/usr/bin/env python
"""colorterm.py: Minimalistic colorful print"""

__author__ = 'hasherezade (hasherezade.net)'
__license__ = "GPL"

BLUE = '\033[94m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
COLOR_END = '\033[0m'
BOLD = "\033[1m"

def color_signed_msg(color, sign, msg):
    if not color or not sign:
        print msg
        return
    print BOLD + color +'[' + sign + '] ' + COLOR_END + msg

def color_msg(color,msg):
    if not color:
        print msg
        return
    print color + msg + COLOR_END

def info(msg):
    color_signed_msg(BLUE, '*', msg)

def good(msg):
    color_signed_msg(GREEN, '+', msg)

def warn(msg):
    color_signed_msg(YELLOW, '!', msg)

def err( msg):
    color_signed_msg(RED, '-', msg)
