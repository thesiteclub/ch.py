#!/usr/bin/python
#
################################################################################
# ch.py v 0.1
# This script checks for ports (defined below) and then prompts the user
# to open the pertinent ones
#
# Ported to Python by George Langdin, george@langdin.com
# Based on a Perl script by jim80net, blog@jim80.net
# Based on a port check script written by Trent Nguyen, tnguyen@serverbeach.com
#
################################################################################

################################################################################
# Import stuff
################################################################################

#import pg			# Postgresql
import sys			# ??
import os			# OS commands
import platform		# OS detection
import subprocess	# OS commands
import re			# RegEx
import ConfigParser # INI config file parser
import argparse		# Cmd line arg parser - requires 2.7
import array		#
import socket		# Network
import time			#

################################################################################
# Variables
################################################################################

# Map platform.system output to variables
# This would be a perfect place for switch/case if Python had it!
os_code = platform.system()

# To call AppleScript from shell use osascript -e 'tell...'

if os_code == 'Darwin':
	os_info = { 'name': 'MacOS', 'lookup': 'host', 'browser': 'open',
	'ssh': 'ssh', 'rdp': 'rdesktop' }
if os_code == 'Windows':
	os_info = { 'name': 'Windows', 'lookup': 'nslookup',
	'browser': 'C:/Progra~1/Mozill~1/firefox.exe',
	'ssh': 'C:/Progra~1/PuTTY/putty.exe -ssh', 'rdp': 'rdesktop' }
if os_code == 'Linux':
	os_info = { 'name': 'Linux', 'lookup': 'host', 'browser': 'firefox',
	'ssh': 'ssh', 'rdp': 'rdesktop' }
if os_code == 'Solaris':
	os_info = { 'name': 'Solaris', 'lookup': 'host', 'browser': 'firefox',
	'ssh': 'ssh' }

# TODO: Generate these based on $USER and/or read from config file
# default username -SSH
defaultUN = "glangdin"
# default username - RDP
defaultUNMicrosoft = "\'ics\\glangdin\'"
defaultdb = 'enf'

timeout = 0.15
socket.setdefaulttimeout(timeout)

# List of ports to check
ports = [21,22,23,25,53,80,110,139,143,389,443,465,636,902,903,993,995,1433,
		1581,2087,3306,3389,5432,8443,15500,23794]

# Perhaps this should be a class (aka object), but this works!
host = {'addr': None, 'alive': False, 'ssh': False, 'rdp': False, 'pgsql': False,
	'whm': False, 'tivoli': False, 'plesk': False, 'innominate': False}

# Parse command line arguments
parser = argparse.ArgumentParser()
parser.add_argument('host', help='IP or name of host')
parser.add_argument('-p', '--ports',
	help='Comma separated list of ports to check or "all"')
parser.add_argument('-v', '--verbose', action='count', default=0,
    help='increase output')
args = parser.parse_args()

# Do input checking?
host['addr'] = args.host
verbose = args.verbose

if args.ports:
	if args.ports == 'all':
		ports = range(1,65535)	# Ports 1 to 65535
	else:
		ports = args.ports.split(',')

nports = len(ports)
maxtime = timeout * nports

################################################################################
# Functions
################################################################################

#-------------------------------------------------------------------------------
# def read_config(level, site_code, message):
	# Read config file
#-------------------------------------------------------------------------------
# def setup(level, site_code, message):

	# Check to see if ch.py is aliased in ~/.bash_profile
	# Create default config file
#-------------------------------------------------------------------------------

def port_scan ():
	print 'Scanning ' + host['addr'] +' (max scan time ' + str(maxtime) + ' seconds)...'
	s = None

	for port in ports:
		for res in socket.getaddrinfo(host['addr'], port, socket.AF_UNSPEC, socket.SOCK_STREAM):
			af, socktype, proto, canonname, sa = res
			try:
				s = socket.socket(af, socktype, proto)
			except socket.error as msg:
				s = None
				continue
			try:
				s.connect(sa)
			except socket.error as msg:
				s.close()
				s = None
				continue
			break
		if s is None:
			continue
		print host['addr'] + ':' + str(port) + ' - OK'
		s.close()
		host['alive'] = True
		if port == 22:
			host['ssh'] = True
		if port == 1581:
			host['tivoli'] = True
		if port == 2087:
			host['whm'] = True
		if port == 3389:
			host['rdp'] = True
		if port == 5432:
			host['pgsql'] = True
		if port == 8443:
			host['plesk'] = True
		if port == 23794:
			host['innominate'] = True

	print 'Finished scanning'

	if host['alive']:
		do_connect()

#-------------------------------------------------------------------------------

# Handles for notdown events
def do_connect():
	print host

	if host['rdp']:
		do_rdp()

	if host['ssh']:
		do_ssh()

	if host['tivoli']:
		open_browser('Tivoli', 1581)

	if host['whm']:
		open_browser('WHM', 2087)

	if host['pgsql']:
		do_pgsql('Postgresql', 5432)

	if host['plesk']:
		open_browser('Plesk', 8443)

	if host['innominate']:
		open_browser('Innominate',23794)

#-------------------------------------------------------------------------------

def do_rdp():
	print '....................'
	print '.   RDP CAPABLE	  .'
	print '....................'
	doit = raw_input('Connect? [y/N]')
	if doit != 'y':
		return

	print 'Connecting to ' + host['addr']
	if os_info['name'] == 'Linux':
		username = defaultUNMicrosoft
		unamein = raw_input('Username to connect as?[' + defaultUNMicrosoft +']')
		if unamein:
			username = unamein
		password = ''
		passwordin = raw_input('Password? [Enter to prompt]')
		if passwordin:
			password = passwordin
		fullscreenin = raw_input('Fullscreen? [y/N]')
		screen = '-g 1260x800 ';
		if fullscreenin == 'y':
			screen = '-f '
		console = raw_input('Attach to console? [y/N]')
		consolo = '-0 '
		subshell.call('rdesktop', screen + consolo + '-r sound:remote -u '
			+ username + ' -p ' + password + ' -a 16 ' + host['addr'] + ' &')
	if os_info['name'] == 'MacOS':
		create_rdp()
		subprocess.call('open /tmp/' + host['addr'] + '.rdp')
	if os_info['name'] == 'Windows':
		subshell.call('mstsc', '/admin /v:'+ host['addr'])

#-------------------------------------------------------------------------------

def open_browser(service, port):
	print '....................'
	print '.   ' + service + ' CAPABLE	  .'
	print '....................'
	if raw_input('Open in browser window? [y/N]') != 'y':
		return
	print 'starting ' + service +'  session'
	subprocess.call(os_info['browser'], 'http://' + host['addr'] + ':' + port + ' &')

#-------------------------------------------------------------------------------

def do_ssh():
	print '....................'
	print '.   SSH CAPABLE    .'
	print '....................'
	doit = raw_input('Connect? [y/N]')
	if doit == 'y':
		print 'Connecting to ' + host['addr']
		username = defaultUN
		unamein = raw_input('Username to connect as? [' + defaultUN + ']')
		if unamein:
			username = unamein
		subprocess.call(os_info['ssh'] + ' ' + username + '@' + host['addr'],shell=True)

#-------------------------------------------------------------------------------

def do_pgsql():
	print '....................'
	print '.  PGSQL CAPABLE   .'
	print '....................'
	doit = raw_input('Connect? [y/N]')
	if doit == 'y':
		print 'Connecting to ' + host['addr']
		username = defaultUN
		unamein = raw_input('Username: [' + defaultUN + ']')
		if unamein:
			username = unamein
		dbname = defaultdb
		dbnamein = raw_input('Database: [' + defaultdb + ']')
		if dbnamein:
			dbname = dbnamein
		subprocess.call(os_info['pgsql'], ' -U ' + username,
			' -h' + host['addr'], '-D ' + dbname)

#-------------------------------------------------------------------------------

# Microsoft's RDP client is free but typical MS garbage.
# It lacks a command line utility and can not be controlled by AppleScript!
# We work around this by creating a file for it to open
# TODO: Let the user set defaults
def create_rdp():
	f = open('/tmp/' + host['addr'] + '.rdp', 'w')
	f.write('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AddToKeychain</key>
	<false/>
	<key>ApplicationPath</key>
	<string></string>
	<key>AudioRedirectionMode</key>
	<integer>0</integer>
	<key>AuthenticateLevel</key>
	<integer>1</integer>
	<key>AutoReconnect</key>
	<true/>
	<key>BitmapCaching</key>
	<true/>
	<key>ColorDepth</key>
	<integer>1</integer>
	<key>ConnectionString</key>
	<string>''' + host['addr'] + '''</string>
	<key>DesktopSize</key>
	<dict>
		<key>DesktopHeight</key>
		<integer>1024</integer>
		<key>DesktopWidth</key>
		<integer>1280</integer>
	</dict>
	<key>Display</key>
	<integer>0</integer>
	<key>Domain</key>
	<string></string>
	<key>DontWarnOnChange</key>
	<false/>
	<key>DontWarnOnDriveMount</key>
	<false/>
	<key>DontWarnOnQuit</key>
	<true/>
	<key>DriveRedirectionMode</key>
	<integer>0</integer>
	<key>FontSmoothing</key>
	<true/>
	<key>FullWindowDrag</key>
	<false/>
	<key>HideMacDock</key>
	<false/>
	<key>KeyMappingTable</key>
	<dict>
		<key>UI_ALPHANUMERIC_KEY</key>
		<dict>
			<key>MacKeyCode</key>
			<integer>102</integer>
			<key>MacModifier</key>
			<integer>0</integer>
			<key>On</key>
			<true/>
		</dict>
		<key>UI_ALT_KEY</key>
		<dict>
			<key>MacKeyCode</key>
			<integer>4294967295</integer>
			<key>MacModifier</key>
			<integer>2048</integer>
			<key>On</key>
			<true/>
		</dict>
		<key>UI_CONTEXT_MENU_KEY</key>
		<dict>
			<key>MacKeyCode</key>
			<integer>120</integer>
			<key>MacModifier</key>
			<integer>2048</integer>
			<key>On</key>
			<true/>
		</dict>
		<key>UI_CONVERSION_KEY</key>
		<dict>
			<key>MacKeyCode</key>
			<integer>4294967295</integer>
			<key>MacModifier</key>
			<integer>0</integer>
			<key>On</key>
			<false/>
		</dict>
		<key>UI_HALF_FULL_WIDTH_KEY</key>
		<dict>
			<key>MacKeyCode</key>
			<integer>49</integer>
			<key>MacModifier</key>
			<integer>256</integer>
			<key>On</key>
			<true/>
		</dict>
		<key>UI_HIRAGANA_KEY</key>
		<dict>
			<key>MacKeyCode</key>
			<integer>104</integer>
			<key>MacModifier</key>
			<integer>0</integer>
			<key>On</key>
			<true/>
		</dict>
		<key>UI_NON_CONVERSION_KEY</key>
		<dict>
			<key>MacKeyCode</key>
			<integer>4294967295</integer>
			<key>MacModifier</key>
			<integer>0</integer>
			<key>On</key>
			<false/>
		</dict>
		<key>UI_NUM_LOCK_KEY</key>
		<dict>
			<key>MacKeyCode</key>
			<integer>71</integer>
			<key>MacModifier</key>
			<integer>0</integer>
			<key>On</key>
			<true/>
		</dict>
		<key>UI_PAUSE_BREAK_KEY</key>
		<dict>
			<key>MacKeyCode</key>
			<integer>99</integer>
			<key>MacModifier</key>
			<integer>2048</integer>
			<key>On</key>
			<true/>
		</dict>
		<key>UI_PRINT_SCREEN_KEY</key>
		<dict>
			<key>MacKeyCode</key>
			<integer>118</integer>
			<key>MacModifier</key>
			<integer>2048</integer>
			<key>On</key>
			<true/>
		</dict>
		<key>UI_SCROLL_LOCK_KEY</key>
		<dict>
			<key>MacKeyCode</key>
			<integer>107</integer>
			<key>MacModifier</key>
			<integer>0</integer>
			<key>On</key>
			<true/>
		</dict>
		<key>UI_SECONDARY_MOUSE_BUTTON</key>
		<dict>
			<key>MacKeyCode</key>
			<integer>256</integer>
			<key>MacModifier</key>
			<integer>4608</integer>
			<key>On</key>
			<true/>
		</dict>
		<key>UI_WINDOWS_START_KEY</key>
		<dict>
			<key>MacKeyCode</key>
			<integer>122</integer>
			<key>MacModifier</key>
			<integer>2048</integer>
			<key>On</key>
			<true/>
		</dict>
	</dict>
	<key>MenuAnimations</key>
	<false/>
	<key>PrinterRedirection</key>
	<true/>
	<key>RedirectFolder</key>
	<string>/Users/peanutt</string>
	<key>RedirectPrinter</key>
	<string>all</string>
	<key>RemoteApplication</key>
	<false/>
	<key>Themes</key>
	<true/>
	<key>UserName</key>
	<string></string>
	<key>Wallpaper</key>
	<false/>
	<key>WorkingDirectory</key>
	<string></string>
</dict>
</plist>''')
	f.close()

################################################################################
# Main
################################################################################

if verbose:
	print 'Selected ports: ' + str(ports)
	print 'Running in: ' + os_info['name']
	print 'Using: ' + os_info['ssh'] + ', ' + os_info['rdp'] + ', ' + os_info['browser']

subprocess.call([os_info['lookup'], host['addr']])

#Resolve IP if hostname given, also, ensure a hostname is given
#if re.match('^([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})$',host['addr']):
#	print 'IP address given'
#else:
#	print 'hostname given'

print '##########################'

port_scan()

if host['alive'] != True:
	print '......................'
	print ' Server does not appear to be online.'
	print ' 0 to check until it responds,'
	print ' or specify the number of repetitions.'
	print ' [Enter to Quit]'
	print '......................'
	timesin = raw_input()
	if timesin:
		times = timesin
	else:
		sys.exit()

	count = 1
	if times == 0:
		while host['alive'] != True:
			print 'sleeping for 2 seconds....'
			time.sleep(2)
			print '##########################'
			print 'Pass ' + str(count) + ' of ' + str(times)
			port_scan()
			count = count + 1
			print str(count)
	else:
		for count in range(times):
			print 'sleeping for 2 seconds....'
			time.sleep(2)
			print '##########################'
			print 'Pass ' + str(count) + ' of ' + str(times)
			port_scan()
			print str(count)
