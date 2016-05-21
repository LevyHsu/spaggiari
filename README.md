# spaggiari
A Secure Shell (SSH) scanner / bruteforcer controlled via the Internet Relay Chat (IRC) protocol.

*'sans armes, ni haine, ni violence'*

###### Requirments
 - [Python 2.7](http://www.python.org/)
 - [Paramiko Library](http://www.paramiko.org/)
 
###### Commands
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
 
###### Todo
- Create a more accurate and comprehensive spooky list.
- Implement scanning for other services (telnet, ftp, mysql, etc).
- Allow scanning a specific host using deep_combos.
- Use pyinstaller to create a single executable.
- Slow random scans when idle.
