#! /usr/bin/env python
# coding: utf-8

from sh import tail
from parse import compile, parse
from gi.repository import Notify
from gi.repository import Gtk
from subprocess import *

# définition de la callback exécutée lors du clic sur le bouton
def callback(notif_object, action_name, command):
    sp = Popen("sudo -i ls /", shell = True, stdin = PIPE, stdout = PIPE, stderr = PIPE)
    out, err = sp.communicate()
    print out.rstrip(), err.rstrip()

    notif_object.close()
    Gtk.main_quit()

def parsing(name, line):
    try:
        lineList = line.split(name)
        if lineList != None:
            lineList = lineList[1].split(" ")
        result = lineList[0]
    except Exception:
        result = None
    return result

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
        "Firewall has been bloqued a paquet", # titre
        command, # message
        'dialog-information' # icône
    )
    # ajout de notre action sur la notification
    notif.add_action(
        'our_callback', # identifiant
        'Allow the traffic', # texte du bouton
        callback, # function callback de notre bouton
        #None, # user_datas, ce dont vous avez besoin dans la callback
        command # fonction qui supprime les user_datas
    )
    notif.show()
    Gtk.main()