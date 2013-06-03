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

# TODO: Check Python version to ensure it is supported
# TODO: Config file parser
# TODO: Test (and fix) connecting to all services on Win/Mac/Linux
# TODO: Properly handle case when no cmd line arguments are given
# TODO: Check to see if ch.py is aliased in ~/.bash_profile
# TODO: Allow user to set more options for RDP connections

################################################################################
# Import stuff
################################################################################

#import pg			# Postgresql
import sys			#
import os			# OS commands
import platform		# OS detection
import subprocess	# OS commands
import re			# RegEx
import ConfigParser # INI config file parser
import argparse		# Cmd line arg parser - requires 2.7
import array		#
import socket		# Network
import time			#
import ConfigParser	# Config file parser
import getpass		# Easy way to get current username

################################################################################
# Variables
################################################################################

os_username = getpass.getuser()
os_code = platform.system()

# Set defaults that can be changed by config file or command line args
cf_parser = ConfigParser.ConfigParser()

cf_parser.add_section('general')
cf_parser.set('general', 'timeout', '0.15')
cf_parser.set('general', 'ports', '21,22,23,25,53,80,110,139,143,389,443,465,636,902,903,993,995,1433,1581,2087,3306,3389,5432,8443,15500,23794')

if os_code == 'Darwin':
	# To call AppleScript from shell use osascript -e 'tell...'
	cf_parser.set('general', 'browser', 'open')
	cf_parser.set('general', 'lookup', 'host')
	cf_parser.set('general', 'ssh', 'ssh')
	cf_parser.set('general', 'rdp', 'rdesktop')
	cf_parser.set('general', 'mysql', 'mysql')

if os_code == 'Linux' or os_code == 'Solaris':
	cf_parser.set('general', 'browser', 'firefox')
	cf_parser.set('general', 'lookup', 'host')
	cf_parser.set('general', 'ssh', 'ssh')
	cf_parser.set('general', 'rdp', 'rdesktop')
	cf_parser.set('general', 'mysql', 'mysql')

if os_code == 'Windows':
	cf_parser.set('general', 'browser', 'C:/Progra~1/Mozill~1/firefox.exe')
	cf_parser.set('general', 'lookup', 'nslookup')
	cf_parser.set('general', 'ssh', 'C:/Progra~1/PuTTY/putty.exe -ssh')
	cf_parser.set('general', 'rdp', 'rdesktop')
	cf_parser.set('general', 'mysql', 'mysql')

cf_parser.add_section('ssh')
cf_parser.set('ssh', 'username', os_username)

cf_parser.add_section('rdp')
cf_parser.set('rdp', 'domain', 'WORKGROUP')
cf_parser.set('rdp', 'username', os_username)
cf_parser.set('rdp', 'height', '1024')
cf_parser.set('rdp', 'width', '1280')

cf_parser.add_section('pgsql')
cf_parser.set('pgsql', 'username', os_username)
cf_parser.set('pgsql', 'database', 'enf')

cf_parser.add_section('mysql')
cf_parser.set('mysql', 'username', os_username)
cf_parser.set('mysql', 'database', 'enf')

# Perhaps this should be a class (aka object), but this works!
host = {'addr': None, 'alive': False, 'ssh': False, 'rdp': False, 'pgsql': False,
	'whm': False, 'tivoli': False, 'plesk': False, 'innominate': False,
	'http': False, 'https': False, 'mysql': False}

# Parse command line arguments
arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('host', help='IP or name of host')
arg_parser.add_argument('-c', '--config',
	help='Path to (optional) config file')
arg_parser.add_argument('-p', '--ports',
	help='Comma separated list of ports to check or "all"')
arg_parser.add_argument('-s', '--scan', action='count', default=0,
	help='Port scan only')
arg_parser.add_argument('-t', '--timeout',
	help='Max time to wait for a port to respond when scanning', default=0.15)
arg_parser.add_argument('-v', '--verbose', action='count', default=0,
    help='increase output')
arg_parser.add_argument('-V', '--version', action='count', default=0,
    help='Print version')
args = arg_parser.parse_args()

if args.config:
	cf_parser.read(args.config)

# Do input checking?
host['addr'] = args.host
verbose = args.verbose

timeout = cf_parser.getfloat('general', 'timeout')
#timeout = args.timeout
socket.setdefaulttimeout(timeout)

ports = cf_parser.get('general', 'ports').split(',')

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

def check_app(app):
	if app == None:
		return 0

	if os_code == 'Windows':
		if os.access(cf_parser.get('general', app), os.X_OK):
			return 0
	else:
		try:
			rc = subprocess.check_call('which ' + app + '>/dev/null 2>&1', shell=True)
		except subprocess.CalledProcessError as msg:
			print 'Check for app ' + app + 'failed. You probably need to install it.'
			return 0
	return 1

def port_scan ():
	print 'Scanning ' + host['addr'] +' (max scan time ' + str(maxtime) + ' seconds)...'
	s = None

	for port in ports:
		port = int(port)
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
		svcname = socket.getservbyport(port)
		print str(port) + ' (' + svcname + ') - OK'
		s.close()
		host['alive'] = True
		if port == 22:
			host['ssh'] = True
		if port == 80:
			host['http'] = True
		if port == 443:
			host['https'] = True
		if port == 1581:
			host['tivoli'] = True
		if port == 2087:
			host['whm'] = True
		if port == 3306:
			host['mysql'] = True
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

	if host['rdp']:
		do_rdp()

	if host['ssh'] and check_app(cf_parser.get('general', 'ssh')):
		do_ssh()

	if host['http']:
		open_browser('http', 'http://' + host['addr'])

	if host['https']:
		open_browser('http', 'https://' + host['addr'])

	if host['tivoli']:
		open_browser('Tivoli', 'http://' + host['addr'] + ':' + 1581)

	if host['whm']:
		open_browser('WHM', 'http://' + host['addr'] + ':' + 2087)

	if host['pgsql']:
		do_pgsql(5432)

	if host['plesk']:
		open_browser('Plesk', 'http://' + host['addr'] + ':' + 8443)

	if host['innominate']:
		open_browser('Innominate', 'http://' + host['addr'] + ':' + 23794)

#-------------------------------------------------------------------------------

def do_rdp():
	print '....................'
	print '.   RDP CAPABLE	  .'
	print '....................'
	doit = raw_input('Connect? [y/N]')
	if doit != 'y':
		return

	print 'Connecting to ' + host['addr']
	if os_code == 'Linux':
		username = '\\' + cf_parser.get('rdp','domain') + '\\\\' + cf_parser.get('rdp','username')
		unamein = raw_input('Username to connect as?[' + username +'] ')
		if unamein:
			username = unamein
		password = ''
		passwordin = raw_input('Password? [Enter to prompt]')
		if passwordin:
			password = passwordin
		fullscreenin = raw_input('Fullscreen? [y/N]')
		screen = '-g ' + cf_parser.get('rdp','height') + 'x' + cf_parser.get('rdp','width');
		if fullscreenin == 'y':
			screen = '-f '
		console = raw_input('Attach to console? [y/N]')
		console = '-0 '
		subprocess.call('rdesktop', screen + consolo + '-r sound:remote -u '
			+ username + ' -p ' + password + ' -a 16 ' + host['addr'] + ' &')
	if os_code == 'Darwin':
		create_rdp()
		subprocess.call('open', '/tmp/' + host['addr'] + '.rdp')
	if os_code == 'Windows':
		subprocess.call('mstsc', '/admin /v:'+ host['addr'])

#-------------------------------------------------------------------------------

def open_browser(service, URL):
	print '....................'
	print '.   ' + service + ' CAPABLE	  .'
	print '....................'
	if raw_input('Open in browser window? [y/N]') != 'y':
		return
	print 'starting ' + service +'  session'
	subprocess.call(cf_parser.get('general', 'browser') + " '" + URL + "' &", shell=True)

#-------------------------------------------------------------------------------

def do_ssh(command=''):
	print '....................'
	print '.   SSH CAPABLE    .'
	print '....................'
	doit = raw_input('Connect? [y/N]')
	if doit == 'y':
		print 'Connecting to ' + host['addr']
		username = cf_parser.get('ssh','username')
		unamein = raw_input('Username to connect as? [' + username + '] ')
		if unamein:
			username = unamein
		subprocess.call(cf_parser.get('general', 'ssh') + ' ' + username + '@' + host['addr'] + ' "' + command + '"', shell=True)

#-------------------------------------------------------------------------------

def do_pgsql(port):
	print '....................'
	print '.  PGSQL CAPABLE   .'
	print '....................'
	doit = raw_input('Connect? [y/N]')
	if doit == 'y':
		print 'Connecting to ' + host['addr']
		username = cf_parser.get('pgsql','username')
		unamein = raw_input('Username: [' + username + '] ')
		if unamein:
			username = unamein
		dbname = cf_parser.get('pgsql','database')
		dbnamein = raw_input('Database: [' + dbname + '] ')
		if dbnamein:
			dbname = dbnamein
		subprocess.call(cf_parser.get('general', 'pgsql'), ' -U ' + username,
			' -h' + host['addr'], ' -D ' + dbname + ' -p ' + port)

#-------------------------------------------------------------------------------

def do_mysql(port):
	print '....................'
	print '.  MySQL CAPABLE   .'
	print '....................'
	doit = raw_input('Connect? [y/N]')
	if doit == 'y':
		print 'Connecting to ' + host['addr']
		username = cf_parser.get('pgsql','username')
		unamein = raw_input('Username: [' + username + ']')
		if unamein:
			username = unamein
		dbname = cf_parser.get('pgsql','database')
		dbnamein = raw_input('Database: [' + dbname + ']')
		if dbnamein:
			dbname = dbnamein
		subprocess.call(cf_parser.get('general', 'mysql'), ' -u ' + username,
			' -h' + host['addr'], ' -D ' + dbname + ' -P ' + port)


#-------------------------------------------------------------------------------

# Microsoft's RDP client is free but typical MS garbage.
# It lacks a command line utility and can not be controlled by AppleScript!
# We work around this by creating a file for it to open
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
		<integer>''' + parser.set('rdp', 'username', 'height') + '''</integer>
		<key>DesktopWidth</key>
		<integer>''' + parser.set('rdp', 'username', 'width') + '''</integer>
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
	print 'Running on: ' + os_code
	print 'Using: ' + cf_parser.get('general', 'ssh') + ', ' + cf_parser.get('general', 'rdp') + ', ' + cf_parser.get('general', 'browser')

subprocess.call([cf_parser.get('general', 'lookup'), host['addr']])

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
