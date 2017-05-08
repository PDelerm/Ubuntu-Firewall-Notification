#! /usr/bin/env python
# coding: utf-8

import gi
gi.require_version('Notify', '0.7')
gi.require_version('Gtk', '3.0')
from sh import tail
from parse import compile, parse
from gi.repository import Notify
from gi.repository import Gtk
from subprocess import *

# Define callback executed on mouse click
def callback(notif_object, action_name, command):
    sp = Popen("sudo -i ls /", shell = True, stdin = PIPE, stdout = PIPE, stderr = PIPE)
    out, err = sp.communicate()
    print out.rstrip(), err.rstrip()
    notif_object.close()
    Gtk.main_quit()

# time = 0 -> add rule permanently
# time < 0  -> add rule for the session
# time > 0 -> add rules for time minutes
def callback2(notif_object, action_name, command, time):
    if time == 0 :
    	sp = Popen("gksudo ls /", shell = True, stdout = PIPE, stderr = PIPE)
    elif time < 0:
        sp = Popen("gksudo ls /", shell = True, stdout = PIPE, stderr = PIPE)
    else:
        command = "gksudo iptables -A " + command + "; sleep " + str(60 * time) + "; sudo iptables -D " + command
        sp = Popen("gksudo ls /", shell = True, stdout = PIPE, stderr = PIPE)
    print command
    out, err = sp.communicate()
    print out.rstrip(), err.rstrip()
    notif_object.close()
    Gtk.main_quit()

# Define a parsing fonction to get value of the name parameter
def parsing(name, line):
    try:
        lineList = line.split(name)
        if lineList != None:
            lineList = lineList[1].split(" ")
        result = lineList[0]
    except Exception:
        result = None
    return result

try:
    for line in tail("-f", "-n0", "/var/log/ufw.log", _iter=True):
        interface = parsing("IN=", line)
        out = parsing("OUT=", line)
        mac = parsing("MAC=", line)
        src = parsing("SRC=", line)
        dst = parsing("DST=", line)
        proto = parsing("PROTO=", line)
        spt = parsing("SPT=", line)
        dpt = parsing("DPT=", line)

        commandIptables = "INPUT -p " + proto + " -i " + interface + " -s " + src + " -d " + dst
        if dpt != None :
            commadIptables = commandIptables + " --dport " + dpt
        commandIptables = commandIptables + " -j ACCEPT"

        commandUfw = "gksudo ufw allow from " + interface + " to " + out + " proto " + proto
        if dpt != None :
            commandUfw = commandUfw + " port " + dpt

        Notify.init('Ubuntu Firewall Notification')
        notif = Notify.Notification.new(
            "A packet has been bloqued by the firewall", # title
            "command", # message
            'dialog-information' # icon
        )
        # add the custom notification action
        notif.add_action(
            'our_callback',
            'Allow traffic permanently', # Button text
            callback2, # function callback de notre bouton
            commandUfw, # fonction qui supprime les user_datas
            0
        )
        notif.add_action(
            'our_callback',
            'Allow traffic for the session', # Button text
            callback2, # function callback de notre bouton
            # None, # user_data, required data for the callback, For now: nothing
            commandIptables, # fonction qui supprime les user_datas
            -1
        )
        notif.add_action(
            'our_callback',
            'Allow traffic for 30 minutes', # Button text
            callback2, # function callback de notre bouton
            # None, # user_data, required data for the callback, For now: nothing
            commandIptables, # fonction qui supprime les user_datas
            30
        )
        notif.add_action(
            'our_callback',
            'Allow traffic for 1 hour', # Button text
            callback2, # function callback de notre bouton
            # None, # user_data, required data for the callback, For now: nothing
            commandIptables, # fonction qui supprime les user_datas
            60
        )
        notif.show()
        Gtk.main()

except IOError:
    print "Impossible to open file"
