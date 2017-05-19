#! /usr/bin/env python
# coding: utf-8

application = 'ufn'
import gi
gi.require_version('Notify', '0.7')
gi.require_version('Gtk', '3.0')
from sh import tail
from parse import compile, parse
from gi.repository import Notify
from gi.repository import Gtk
from subprocess import *
import gettext
gettext.install(application)

# Define callback executed on mouse click
# time = 0 -> add rule permanently
# time < 0  -> add rule for the session
# time > 0 -> add rules for time minutes
def callback(notif_object, action_name, command, time):
    if time == 0 :
        sp = Popen("gksudo " + command, shell = True, stdout = PIPE, stderr = PIPE)
    elif time < 0:
        sp = Popen("gksudo iptables -A " + command, shell = True, stdout = PIPE, stderr = PIPE)
    else:
        tmpFile = open("/tmp/ufn.dat", "w")
        tmpFile.write("gksudo iptables -D " + command)
        tmpFile.close()
        
        command = "gksudo iptables -A " + command #+ "; at now +" + str(time) + " minutes -f /tmp/ufn.dat"
        sp = Popen(command, shell = True, stdout = PIPE, stderr = PIPE)
        sp = Popen("at now +" + str(time) + " minutes -f /tmp/ufn.dat", shell = True, stdout = PIPE, stderr = PIPE)
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
            commandIptables = commandIptables + " --dport " + dpt
        commandIptables = commandIptables + " -j ACCEPT"

        commandUfw = "ufw allow from " + interface + " to " + out + " proto " + proto
        if dpt != None :
            commandUfw = commandUfw + " port " + dpt

        Notify.init('Ubuntu Firewall Notification')
        notif = Notify.Notification.new(
            _("Ubuntu Firewall Notification"), # title
            _("A packet has been bloqued by the firewall"), # message
            'dialog-information' # icon
        )
        # add the custom notification action
        notif.add_action(
            'permanent',
            _('Allow traffic permanently'), # Button text
            callback, # function callback de notre bouton
            commandUfw, # fonction qui supprime les user_datas
            0
        )
        notif.add_action(
            'session',
            _('Allow traffic for the session'), # Button text
            callback, # function callback de notre bouton
            # None, # user_data, required data for the callback, For now: nothing
            commandIptables, # fonction qui supprime les user_datas
            -1
        )
        notif.add_action(
            '30minutes',
            _('Allow traffic for 30 minutes'), # Button text
            callback, # function callback de notre bouton
            # None, # user_data, required data for the callback, For now: nothing
            commandIptables, # fonction qui supprime les user_datas
            30
        )
        notif.add_action(
            '60minutes',
            _('Allow traffic for 1 hour'), # Button text
            callback, # function callback de notre bouton
            # None, # user_data, required data for the callback, For now: nothing
            commandIptables, # fonction qui supprime les user_datas
            60
        )
        notif.show()
        Gtk.main()

except IOError:
    print "Impossible to open file"
