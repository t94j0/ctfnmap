# CTFNmapScanner
An easy way to manage nmap scans during a CTF

### Warning: There is command injection, so don't run this as root on an xinetd broadcasting to the world...

There is a CTFHost server located at ` http://ctfhosts.maxh.io/` that can be used for free

# TODO
* ~~Save scans locally, so you don't have to rescan~~
* Show diffs when rescanning
* ~~Make server for teams to use the same scans~~

# Usage:
|Command Name/Usage  |  Use                              |
|--------------------|-----------------------------------|
|scan [ip [ip2...]]  | Scan IPs                          |
|     show           | Show hosts scanned                |
| list [ip]          | List ports for the specified IP   |
| help               | Lists commands that can be used   |
| get [project name] | Gets a scan from http source      |
| set [project name] | Sets data for other people to use |

