import urllib.request
import urllib.parse
import re

stop_statement=0
port_to_connect="3010"
ip_to_connect='10.10.177.12'

url = "http://%s:%s" % (ip_to_connect,port_to_connect)
ws = urllib.request.urlopen(url)
read_data = ws.read().decode('utf-8')
print("The read data is:", read_data)
pattern = r"(\d+)"
if re.match(pattern, read_data):
    match = re.match(pattern, read_data)
    stop_statement=1
    print ("After RE:",match.group(0))
else:
    print ("After RE: No match")
