import requests
import csv
import json
import time
import hashlib
import sys
import argparse

api_key="XXXXXXXXXXXX" #INSERT API-KEY HERE

def check_masshashes(tobehashed,path): #function for checking txt-file with multiple hashes
 with open(tobehashed, 'r') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter='\n')
        stack = []
        line=1
        for line in csv_reader:
            print("import Hash {} into Stack".format(line))
            stack.append(line)
        newfile= open(path, 'a')
        while stack:
          gethash=stack.pop()
          gethash=( ", ".join( str(e) for e in gethash ) )
          x=printresult(gethash)
          newfile.write("MD5: {} \nlast scanned: {} \nscore:{}/{} \nlink.: {} \n\n" .format(x.get('md5'),x.get('scan_date'),x.get('positives'),x.get('total'),x.get('permalink')))
          if len(stack) > 0 :
            progressbar()
        newfile.close()
        print("\ndone. Check your results at {}".format(path))



def hash_file(tobehashed):
    hash_md5 = hashlib.md5()
    with open(tobehashed, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
        print (hash_md5.hexdigest())
        return hash_md5.hexdigest()


def vt_upload(upload):
    
    params = {'apikey': api_key}
    print("\nuploading file,  please wait\n")
    files = {'file': (upload, open(upload, 'rb')) }
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
    json_response = response.json()
    if (json_response.get('response_code')) == 1:
      print("upload successful, file queued for analysis. \n\nuse this script later with option --hash {} to get the results ".format(json_response.get('md5')))
    else:
      print("upload failed.")


def vt_getresult(hashes):
  headers = {
    "Accept-Encoding": "gzip, deflate",
    "User-Agent" : "gzip,  My Python requests library example client or username"
    }
  params = {'apikey': api_key , 'resource':hashes}
  response = requests.post('https://www.virustotal.com/vtapi/v2/file/report', params=params , headers=headers)
  json_response = response.json()

  return json_response

def printresult(hash):
  getresult = vt_getresult(hash)
  print("\nMD5 HASH:{}" .format(hash))
  if sys.argv[2] != hash:
    print ("origin file name: {}".format(sys.argv[2]))
  print("last scanned: {}" .format(getresult.get('scan_date')))
  print("score:{}/{}".format(getresult.get('positives'),getresult.get('total')))
  print("link.: {} \n".format(getresult.get('permalink') ))
  return getresult


def progressbar():
  toolbar_width = 30
  print("____________________________________________\n")
  print("Waiting 15 Sec. to prevent free API timeout\n")
  print("____________________________________________\n")
  sys.stdout.write("[%s]" % (" " * toolbar_width))
  sys.stdout.flush()
  sys.stdout.write("\b" * (toolbar_width+1)) 
  for i in range(toolbar_width):
      time.sleep(0.5) 
      sys.stdout.write("-")
      sys.stdout.flush()
  sys.stdout.write("\n")


def main():
    __authors__ = ["Egon | @plonxyz"]
    __date__ = "2019-04-16"
    __description__ = "Checks hashes and files at VirusTotal , supported: MD5,SHA1,SHA256 , all kind of files"

    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(", ".join(__authors__), __date__)
    )

    parser.add_argument("--hash", help="checks hash at VT")
    parser.add_argument("--upload", help="uploads file to VT for scanning (NOT SUITABLE FOR CONFIDENTIAL STUFF!)")
    parser.add_argument("--file", help=" hashes file and checks hash at VT")
    parser.add_argument("--mass", help=" reads multiple hashes out of a txt file and checks them at VT , needs --output for results")
    parser.add_argument("--output",help= "specify outputpath for mass-check")

    args = parser.parse_args()

    if args.mass and args.output:
        check_masshashes(args.mass,args.output)
    elif args.mass:
        print("please use --output for output-file")
    if args.hash:
        printresult(args.hash)
    if args.upload:
         vt_upload(args.upload)
    if args.file:
        printresult(hash_file(args.file))
    
  
if __name__ == "__main__":
      main()
      pass
   


