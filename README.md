# ctf-web-enum v1.0

This tool allows you perform a little enumeration scan on a target in order to get usefull informations

## 🎯 Features
![image](https://github.com/hashgrem/ctf-web-enum/assets/44004683/7c8c3fe1-2303-4eb8-b655-7e2a45bcd9ea)

## 🛠️ Install

First of all, you need python3 to use this tool, you can download it from this link: https://www.python.org/downloads/

Next, you can download the zip version on github, or traditionally clone the repository from your command line:
```
git clone https://github.com/hashgrem/ctf-web-enum.git
```
After dowloading, you'll need to install libraries to run the script correctly. You can run the following command:

```
cd ctf-web-enum/

pip install -r requirements.txt
```

## 📈 Usage

Just specify url you want to test:

```
python ctf-web-enum.py.py -h

usage: ctf-web-enum.py.py [-h] -u URL

options:
  -h, --help         show this help message and exit
  -u URL, --url URL  url you want to scan
```

## ✍️ Example

```
python ctf-web-enum.py.py -u http://example.com/
```

## 🧏‍♂️ Disclaimer

Sometimes in CTF, directory and file scanning isn't allowed. So, don't forget to read rules and if it's not allowed, comment the `check_backup_files()` function's call.


