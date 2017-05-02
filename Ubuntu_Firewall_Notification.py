#! /usr/bin/env python
# coding: utf-8

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

        command = "sudo ufw allow from " + interface + " to " + out + " proto " + proto
        # sudo ufw allow from <target> to <destination> port <port number> proto <protocol name>
        if dpt != None:
            command = command + " port " + dpt

        Notify.init('Ubuntu Firewall Notification')
        notif = Notify.Notification.new(
            "A packet has been bloqued by the firewall", # title
            command, # message
            'dialog-information' # icon
        )
        # add the custom notification action
        notif.add_action(
            'our_callback',
            'Allow traffic', # Button text
            callback, # function callback de notre bouton
            # None, # user_data, required data for the callback, For now: nothing
            command # fonction qui supprime les user_datas
        )
        notif.show()
        Gtk.main()

except IOError:
    print Impossible to open file
