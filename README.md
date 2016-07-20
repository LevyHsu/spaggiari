# spaggiari
A Secure Shell (SSH) scanner / bruteforcer that can be controlled via the Internet Relay Chat (IRC) protocol.

#####*'sans armes, ni haine, ni violence'*

###### Requirments
 - [Paramiko Library](http://www.paramiko.org/)
 
###### Information
Spaggiari scanner comes in 2 versions, a CLI version and an IRC version.

The CLI version can be used directly from the command line.

The IRC version can be used to run the bot on many machines and control them from IRC.

You must edit the config in the IRC version in order to have the bot connect.

###### CLI Commands
**Usage:** spaggiari.py [OPTIONS] [SCAN]

| Option | Description |
| --- | --- |
| -d | enable deep scanning. |
| -f | enable fast scanning. |
| -o \<path> | save output from scan(s) to file. |



| Scan | Description |
| --- | --- |
| -l \<path> | scan a list of ip addresses from file. |
| -x | scan random ip addresses. (does not stop) |
| -r \<class> \<range> | scan a range of ip addresses. |
| -t \<ip> | scan a target ip address. |

Deep scanning uses a larger list of combos to bruteforce with.

###### IRC Commands
| Command | Description |
| --- | --- |
| @info \<id/all> | Information about the server. |
| @kill \<id/all> | Kill the bot. |
| @random \<id/all> | Scan random ip addresses. |
| @range \<id> \<class> \<range> | Scan a range of ip addresses. |
| @range \<id> \<class> random | Scan a random range of ip addresses. |
| @status \<id/all> | Check the scanning status on the bot. |
| @stop \<id/all> | Stop all current running scans. |

*Note:* Commands require either 'all' or the bots unique id after it.

If the bot has a nick of 'spag-tnnxu', the id of that bot is 'tnnxu'.

You can issue a command with `@info all`, or `@info tnnxu`.

The <class> can be b or c. The <range> is the ip address range prefix to scan.

**CLI Examples:**
* `spaggiari.py -r b 192.168`   *(Scans the range 192.168.0.0-192.168.255.255)*
* `spaggiari.py -r c 192.168.1` *(Scans the range 192.168.1.0-192.168.1.255)*
* `spaggiari.py -r b random`    *(Scans the range ?.?.0.0-?.?.255.255)*
* `spaggiari.py -r c random`    *(Scans the range ?.?.?.0-?.?./.255)*
    
**IRC Examples:**
* `@range tnnxu b 192.168`   *(Scans the range 192.168.0.0-192.168.255.255)*
* `@range tnnxu c 192.168.1` *(Scans the range 192.168.1.0-192.168.1.255)*
* `@range tnnxu b random`    *(Scans the range ?.?.0.0-?.?.255.255)*
* `@range tnnxu c random`    *(Scans the range ?.?.?.0-?.?./.255)*
 
###### Todo
* Create a more accurate and comprehensive spooky list.
* Use pyinstaller to create a single executable.
