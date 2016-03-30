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
| @scan \<id> \<start> \<end> | Example: `@scan tnnxu 10.13.56.113 10.29.23.200` *(Scans every IP from 10.13.56.113 to 10.29.23.200)* |
| @scan \<id> a \<range> | Example: `@scan tnnxu 107` *(Scans every IP from 107.0.0.0    to 107.255.255.255)* |
| @scan \<id> b \<range> | Example: `@scan tnnxu 107.13` *(Scans every IP from 107.13.0.0   to 107.13.255.255)* |
| @scan \<id> c \<range> | Example: `@scan tnnxu 107.13.201` *(Scans every IP from 107.13.201.0 to 107.13.201.255)* |
| @scan \<id> \<a/b/c> random | Example: `@scan tnnxu b random` *(Scans every IP from ?.?.0.0 to ?.?.255.255)* |
| @status \<id/all> | Check the scanning status on the bot. |
| @stop \<id/all> | Stop all current running scans. |
| @version \<id/all> | Information about the scanner. |

*Note:* Commands require either 'all' or the bots unique id after it.

If the bot has a nick of 'spag-tnnxu', the id of that bot is 'tnnxu'.

You can issue a command with `@info all`, or `@info tnnxu`.

###### Bugs
- Using `combos.keys()` is in ABC order and not testing 'root' first.
- Long range ip scans may consume memory and crash.
- The `@stop` command is not perfect and doesn't fully stop scans in progress.
 
###### Todo
- Create a more accurate and comprehensive spooky list.
- Implement scanning for telnet and ftp.
- Make use of `deep_combos` after no successful logins.
- Use pyinstaller to create a single executable.
- Give up after x amount of timeouts.
- Slow random scans when idle.
