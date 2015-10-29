#HashGate
HashGate is a tool that can be used to detect file modifications in a specified directory, this is great for detecting when a site has been hacked and what files have been infected.

##Synopsis
hashgate.py [-h] -ca CACHE -f FILES -t {update,check} [-w WHITELIST] [-vt VIRUSTOTALAPIKEY]


##Description
#####required arguments:
the full path to the cache file

`-ca CACHE, --cache CACHE`

the full path to the files to check

`-f FILES, --files FILES`

specify task to perform

`-t {update,check}, --task {update,check}`

#####optional arguments:
show this help message and exit

`-h, --help`

the full path to whitelist file

`-w WHITELIST, --whitelist WHITELIST`

specify your VirusTotal API key for checking if modified files have been flagged by VT.
(warning: this is slow due to API req limits)

`-vt VIRUSTOTAL, --virustotal VIRUSTOTAL`

##Example Usage
Display Help:

`./hashgate.py -h`

Check the contents of /directory/example/

`./hashgate.py -ca example.cache -f /directory/example -t check`

Update the contents of example.cache to the current contents of /directory/example

`./hashgate.py -ca example.cache -f /directory/example -t update`


