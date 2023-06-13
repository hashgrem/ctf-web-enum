from colorama import Fore, Back, Style, init
import requests
import re
import sys
from datetime import datetime
import time

def is_valid_url(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

def lil_nikto_scan(url):
    try:
        if is_valid_url(url):
            response = requests.get(url)
        else:
            print(f">>> {Fore.RED}[!] Incorrect url format{Style.RESET_ALL}")
            sys.exit()
    except requests.exceptions.RequestException as e:
        print(f">>> {Fore.RED}[!] Error while operating : {e}{Style.RESET_ALL}")
        sys.exit(1)

    server = response.headers.get("Server")
    x_powered_by = response.headers.get("X-Powered-By")

    if server is not None:
        print(f">>> {Fore.GREEN}[+] Webserver is  : {server}{Style.RESET_ALL}")
    if x_powered_by is not None:
        print(f">>> {Fore.GREEN}[+] Webserver uses :  {x_powered_by}{Style.RESET_ALL}")
    
    if "Content-Encoding" in response.headers:
        print(f">>> {Fore.YELLOW}[-] The server supports compression.{Style.RESET_ALL}")
    else:
        print(f">>> {Fore.YELLOW}[-] The server doesn't support compression.{Style.RESET_ALL}")
      
    version_regex = re.compile(r"\d+\.\d+(\.\d+)?")
    for header in response.headers:
        match = version_regex.search(response.headers[header])
        if match:
            print(f">>> {Fore.GREEN}[+] Version found : {match.group(0)} {Style.RESET_ALL}")
        
    if response.status_code in [301, 302]:
        loca_header = response.headers.get("Location")
        print(f">>> {Fore.GREEN}[+] Target URL uses redirection towards : {loca_header}{Style.RESET_ALL}")
    else:
        print(f">>> {Fore.YELLOW}[-] Target URL don't use any redirection{Style.RESET_ALL}")
        
    if response.status_code == 401:
        print(f">>> {Fore.YELLOW}[-] Target URL is protected by a basic HTTP authentication{Style.RESET_ALL}")
    else:
        print(f">>> {Fore.YELLOW}[-] Target URL isn't protected by a basic HTTP authentication{Style.RESET_ALL}")

    headers = {
        "X-Frame-Options": "",
        "X-XSS-Protection": "",
        "X-Content-Type-Options": ""
    }

    try:
        response = requests.get(url, headers=headers)

        header1 = "The anti-clickjacking X-Frame-Options header is not present."
        header2 = "The X-XSS-Protection header is not defined."
        header3 = "The X-Content-Type-Options header is not set."

        if "X-Frame-Options" not in response.headers:
            print(f">>> {Fore.GREEN}[+] {header1}{Style.RESET_ALL}")
        if "X-XSS-Protection" not in response.headers:
            print(f">>> {Fore.GREEN}[+] {header2}{Style.RESET_ALL}")
        if "X-Content-Type-Options" not in response.headers:
            print(f">>> {Fore.GREEN}[+] {header3}{Style.RESET_ALL}")
    except:
        print("[!] Error occured while sending request to the URL")

def check_robots_txt(url):
    try:
        r = requests.get(url + "/robots.txt")
        if r.status_code == 200:
            print(f">>> {Fore.GREEN}[+] robots.txt is publicly accessible.{Style.RESET_ALL}")
            print(f">>> {Fore.GREEN}[+] Content of robots.txt: {Style.RESET_ALL}\n" + r.text)
        else:
            print(f">>> {Fore.YELLOW}[-] robots.txt is not publicly accessible.{Style.RESET_ALL}")
    except requests.exceptions.RequestException as e:
        print(">>> [-] Exception Occured: " + str(e))

def check_sitemap(url):
    try:
        r = requests.get(url + "/sitemap.xml")
        if r.status_code == 200:
            print(f">>> {Fore.GREEN}[+] sitemap.xml is publicly accessible.{Style.RESET_ALL}")
        else:
            print(f">>> {Fore.YELLOW}[-] sitemap.xml is not publicly accessible.{Style.RESET_ALL}")
    except requests.exceptions.RequestException as e:
        print(">>> [-] Exception Occured: " + str(e))

def check_cookies(url):
	session = requests.Session()
	cookie = session.cookies.get_dict()

	if len(cookie) > 0:
		print(f">>> {Fore.GREEN}[+] Some cookies has been found{Style.RESET_ALL}")
	else:
		print(f">>> {Fore.YELLOW}[-] No cookies found.{Style.RESET_ALL}")

def find_github(url):
    try:
        r = requests.get(url + ".git")
        valid_codes = [200, 204, 301, 302, 307, 401, 403, 407]
        if r.status_code in valid_codes:
            print(f">>> {Fore.GREEN}[+] A github repository has been found. Might be vulnerable to gitDumper{Style.RESET_ALL}")
        else:
            print(f">>> {Fore.RED}[-] No github repository found.{Style.RESET_ALL}")
    except requests.exceptions.RequestException as e:
        print(f">>> {Fore.RED}[-] Exception Occured: {e}{Style.RESET_ALL}")

def check_backup_files(url):
	ext = ["",".sql",".json", ".jsp", ".bin", ".xlsx", ".rtf", ".docx", ".env", ".js", ".inc", ".asa", ".config", ".java", ".asp",".aspx",".xml",".do",".pdf",".json",".php",".backup",".bck",".old",".save",".bak",".sav","~",".copy",".old",".orig",".tmp",".txt",".back",".bkp",".bac",".tar",".gz",".tar.gz",".zip",".rar"]
	file_names = ["config", "index", "backup", "conf", "login", "log", "logs", ".php", "site", ".htaccess", ".htpasswd", ".zip", "admin", "administrator","app", "archive", "private"]
	valid_codes = [200, 204, 301, 302, 307, 401, 403, 407]

	if is_valid_url(url):
		found = 0
		count = 0
		for file in file_names:
			for e in ext:
				r = requests.get(url+file+e)
				count += 1
				if r.status_code in valid_codes:
					print(f">>> {Fore.GREEN}[+] Backup file found ! --> {file}{e}{Style.RESET_ALL}")
					found += 1
		if found == 0:
			print(f">>> {Fore.RED}[-] 0 backup file found ({count} tested){Style.RESET_ALL}")

if __name__ == "__main__":

	init()
	URL = "http://localhost:1234/"
	print("\n--------------------------------------------")
	print("  Target: "+ URL)
	print(f"  Started at: {datetime.now()}")
	print("--------------------------------------------\n")
	lil_nikto_scan(URL)
	check_robots_txt(URL)
	check_sitemap(URL)
	find_github(URL)
	check_cookies(URL)
	check_backup_files(URL)