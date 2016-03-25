# spaggiari
A Secure Shell (SSH) scanner / bruteforcer controlled via the Internet Relay Chat (IRC) protocol.

'sans armes, ni haine, ni violence'

Requirments:
 - Python 2.7       (http://www.python.org/)
 - Paramiko Library (http://www.paramiko.org/)
 
Commands:
 - @help      | A list of commands, syntax, and descriptions.
 - @info      | Information about the server.
 - @kill      | Kill the bot.
 - @scan      | Scan every in IP address in the range arguments.
 - @status    | Check the scanning status on the bot.
 - @stop      | Stop all current running scans.
 - @version   | Information about the scanner.

Note: Commands require either 'all' or the bots unique id after it.

If the bot has a nick of 'spag-tnnxu', the id of that bot is 'tnnxu'.

You can issue a command with '@info all', or '@info tnnxu'.

Bugs:
- Using combos.keys() is in ABC order and not testing 'root' first.
- Long range ip scans may consume memory and crash.
- The @stop command is not perfect and doesn't fully stop scans in progress.
 
Todo:
- Create a more accurate and comprehensive spooky / dns list.
- Implement scanning for telnet and ftp.
- Make use of 'deep_combos' after no successful logins.

# Legal Disclaimer
It is the end user's responsibility to obey all applicable local, state and federal laws.

Developers assume no liability and are not responsible for any misuse or damage caused by this program.
