# VThash-checker

Python script to check hashes and files at VirusTotal.

Supported python version: 3
####
Supported hashes: MD5, SHA1, SHA256

## Dependencies
Python Modules: pip3 install requests , pip3 install simplejson  
####
API-KEY from www.virustotal.com

## functions and how to use 
```
* Check single hash
* Check multiple hashes from a txt file
* Hash files and check the hash 
* Upload a file for scanning



usage: hashcheck.py [-h] [--hash HASH] [--upload UPLOAD] [--file FILE]
                    [--mass MASS] [--output OUTPUT]

optional arguments: 
  -h, --help                  show this help message and exit
  --hash HASH                 checks hash at VT
  --upload example.exe        uploads file to VT for scanning (NOT SUITABLE FOR
                              CONFIDENTIAL STUFF!)
  --file example.exe           hashes file and checks hash at VT
  --mass hashes.txt           reads multiple hashes out of a txt file and checks them at
                              VT , needs --output for results
  --output /path/result.txt  specify outputpath for mass-check
 ```
  
###

Published under GNU General Public License v3.0
