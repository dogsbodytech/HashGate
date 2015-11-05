#HashGate
HashGate is an intrusion detection tool that can be used to detect file modifications in a specified directory.

##Synopsis
hashgate.py [-h] -ca CACHE -f FILES -t {update,check} [-w WHITELIST] [-vt VIRUSTOTALAPIKEY]


##Description
#####Required arguments:
The full path to the cache file

`-ca CACHE, --cache CACHE`

The full path to the files to check

`-f FILES, --files FILES`

Specify task to perform

`-t {update,check}, --task {update,check}`

#####Optional arguments:
Show this help message and exit

`-h, --help`

The full path to whitelist file

`-w WHITELIST, --whitelist WHITELIST`

Specify your VirusTotal API key for checking if modified files have been flagged by VT.
(warning: this is slow due to API req limits)

`-vt VIRUSTOTAL, --virustotal VIRUSTOTAL`

##Example usage
Display Help:

`./hashgate.py -h`

Check the contents of /directory/example/

`./hashgate.py -ca example.cache -f /directory/example -t check`

Update the contents of example.cache to the current contents of /directory/example

`./hashgate.py -ca example.cache -f /directory/example -t update`


