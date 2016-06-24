# spaggiari
A Secure Shell (SSH) scanner / bruteforcer controlled via the Internet Relay Chat (IRC) protocol.

###*'sans armes, ni haine, ni violence'*

##### Requirments
 - [Paramiko Library](http://www.paramiko.org/)
 
##### Information
Spaggiari scanner comes in 2 versions. A CLI version and an IRC version.
The CLI version can be used directly from the command line.
The IRC version can be used to run the bot on many machines and control them from IRC.
You must edit the config in the IRC version in order to have the bot connect.

##### CLI Commands
**Usage:** spaggiari.py [OPTIONS] [SCAN]
| Option | Description |
| --- | --- |
| -d | option: enable deep scanning. |
| -o \<path> | option: save output from scan(s) to file. |

**options:** spaggiari.py [OPTIONS] [SCAN]
| Scan | Description |
| --- | --- |
| -l \<path> | scan a list of ip addresses from file. |
| -x | scan random ip addresses. |
| -r \<class> \<range> | scan a range of ip addresses. |
| -t \<ip> | scan a target ip address. |

Deep scanning uses a larger list of combos to bruteforce with.
The <class> can be b or c. The <range> is the ip address range prefix to scan.
Example: spaggiari -r b 192.168   (Scans the range 192.168.0.0-192.168.255.255)
Example: spaggiari -r c 192.168.1 (Scans the range 192.168.1.0-192.168.1.255)

 
##### IRC Commands
| Command | Description |
| --- | --- |
| @help \<id> | A list of commands, syntax, and descriptions. |
| @info \<id/all> | Information about the server. |
| @kill \<id/all> | Kill the bot. |
| @scan \<id> b \<range> | Example: `@scan tnnxu 107.13` *(Scans from 107.13.0.0   to 107.13.255.255)* |
| @scan \<id> c \<range> | Example: `@scan tnnxu 107.13.201` *(Scans from 107.13.201.0 to 107.13.201.255)* |
| @scan \<id> \<b/c> random | Example: `@scan tnnxu b random` *(Scans from ?.?.0.0 to ?.?.255.255)* |
| @status \<id/all> | Check the scanning status on the bot. |
| @stop \<id/all> | Stop all current running scans. |

*Note:* Commands require either 'all' or the bots unique id after it.

If the bot has a nick of 'spag-tnnxu', the id of that bot is 'tnnxu'.

You can issue a command with `@info all`, or `@info tnnxu`.
 
##### Todo
- Create a more accurate and comprehensive spooky list.
- Implement scanning for other services (telnet, ftp, mysql, etc).
- Allow scanning a specific host using deep_combos.
- Use pyinstaller to create a single executable.
- Slow random scans when idle.
