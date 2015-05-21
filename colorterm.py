#!/usr/bin/env python
"""colorterm.py: Minimalistic colorful print"""

__author__ = 'hasherezade (hasherezade.net)'
__license__ = "GPL"

GREY = '\033[90m'
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
PURPLE = '\033[95m'
LIGHTBLUE = '\033[96m'
BG_RED = '\033[6;30;41m'
BG_GREY = '\033[6;37;40m'

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

def color_bold_msg(color, msg):
    if not color:
        print msg
        return
    print BOLD + color + msg + COLOR_END

def info(msg):
    color_signed_msg(BLUE, '*', msg)

def good(msg):
    color_signed_msg(GREEN, '+', msg)

def warn(msg):
    color_signed_msg(YELLOW, '!', msg)

def err( msg):
    color_signed_msg(RED, '-', msg)
