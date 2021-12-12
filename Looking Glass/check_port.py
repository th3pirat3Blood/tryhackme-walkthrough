#!/usr/bin/python3

import subprocess
import sys

port_file = ""
ip = ""

def initial():
	global port_file, ip
	if len(sys.argv) == 3:
		port_file = sys.argv[1]
		ip = sys.argv[2]
	else:
		print("Usage: python3 script.py <ports-file> <IP>")
		exit(0)


def read_file():
	global port_file
	with open(port_file, "r") as f:
		data = f.read()
	return data.split("\n")[:-1]


def ssh_connect(port_list):
	global ip
	start = 0
	last = len(port_list)-1
	while start<=last:
		index = int((start + last)/2)
		port = port_list[index]

		response = subprocess.run(["ssh", f"alice@{ip}", f"-p{port}"], capture_output=True).stdout
		if response == b'Lower\r\n':
			print(f"Checking higher port than {port}")
			start = index+1
		elif response == b'Higher\r\n':
			print(f"Checking lower port than {port}")
			last = index-1
		else:
			print(f"Found service at port: {port}")
			exit(0)

	print("Nothing Found")


initial()
print(f"Using ports in file: \'{port_file}\' on IP: {ip}\n")
port_list = read_file()
print(f"Using following ports:\n{port_list}\n")

ssh_connect(port_list)
