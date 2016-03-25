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
 
 Todo:
- Fix up the @stop command.
- Create a more accurate spooky list.
- Add telnet/ftp scanning support.
- Limit range size due to memory consumption.
