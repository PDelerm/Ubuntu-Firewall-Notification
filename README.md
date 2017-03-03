# Ubuntu-Firewall-Notification
Ubuntu, like Windows, comes with an integrated Firewall. This firewall
is disabled by default, and rare are the users who activate it.
For those few security-conscious users, handling the Firewall is far
from intuitive. A tool: gufw allows to do the initial configuration,
but once the configuration is done and the Firewall is deployed,
it is essentially silent: the only way to know that it does something
is to look at the log files. Apart from these logs, there is no indication
to the users that packages are blocked, which can be very inconvenient
in certain situations.
Example: The Firewall is configured to pass the HTTP and HTTPS outgoing traffic
but the captive portal of the student residence sends an HTTP request on
the non-standard 8080 port. As a result the student finds himself with a web
page that does not respond After he has entered his credentials.
Managing the Firewall is one of the functions that Windows handles better than
Linux distributions at present: In such a situation on Windows, a popup would
appear informing the user that Firefox wants to access the Internet on port 8080,
and Asking the user if he wants to allow or prohibit this action.
The goal of this project is to create a program to facilitate user / firewall
interactions. This is a real project with a concrete benefit for the community
and we will have to aim for an inclusion of the program in Ubuntu MATE 17.10.

Technologies: Python / C / C ++, Linux, Ubuntu, IPv4, IPv6, iptables, ufw,
D-Bus, GTK +