# modman

`modman` is a small program for managing multiple Minecraft modpacks on a single server. Each modpack is a folder under `/srv/minecraft`. You type commands at a prompt instead of managing the different modpacks by hand.

## Install it

Put this project folder somewhere permanent, for example `~/.local/share/modman`. The `bin` and `data` folders need to stay next to each other.

Make the program executable:

```bash
chmod +x ~/.local/share/modman/bin/modman
```

Add that `bin` folder to your `PATH` so you can run `modman` from any directory. Add this line to `~/.bashrc`:

```bash
export PATH="$HOME/.local/share/modman/bin:$PATH"
```

Then open a new terminal, or run `source ~/.bashrc`, so the change takes effect.

## Start it

Open a terminal and run:

```bash
modman
```

You get a `modman>` prompt. Type a command and press Enter. Type `help` to see the command list again, or `exit` to leave.

The Up and Down arrow keys recall commands you have typed before. Tab finishes a command or a server name.

## Which servers start on boot

The file `data/index.txt` is the list of servers that belong to the boot service (`mc-servers.service`). One server name per line. Servers in that list are the ones `start`, `stop`, `restart`, and `status` manage as a group. That file is local to each machine. Copy `data/index.txt.example` to `data/index.txt` to start a new list.

`add` and `remove` change that list. `remove` stops the server first if it is running, then takes it off the list. The server folder stays on disk.

## See what is going on

| Command | What it shows |
| --- | --- |
| `list` | Servers in the index, with Java version, port, and whether each one is stopped, starting, or running |
| `available` | Server folders that exist but are not in the index |
| `status` | The same running/stopped view for every indexed server |
| `status Cobbleverse` | That view for one server |
| `usage` | CPU, memory, and how long each indexed server has been up |
| `usage Cobbleverse` | Those numbers for one server |

A server that is not running shows `-` for CPU, memory, and uptime.

Status words:

- **stopped** means there is no live screen session.
- **starting** means the screen is up, and the server has not printed that it is done loading yet.
- **running** means startup has finished.

If two servers are set to the same port, their names show up highlighted. They will not both start properly until the ports differ.

## Start, stop, and watch a server

| Command | What it does |
| --- | --- |
| `start` | Starts every indexed server that is not already running |
| `start Cobbleverse` | Starts that server |
| `stop` | Stops every indexed server |
| `stop Cobbleverse` | Stops that server |
| `restart` | Stops and starts every indexed server |
| `restart Cobbleverse` | Stops and starts that server |
| `join Cobbleverse` | Opens that server's live console |

Leave the console with **Ctrl-A**, then **d**. That detaches and returns you to the `modman>` prompt. The server keeps running.

## The boot service

These commands talk to `mc-servers.service`, the service that starts the indexed servers at boot.

| Command | What it does |
| --- | --- |
| `service status` | Shows whether that service is up |
| `service start` | Starts the service, which starts any indexed server that is not already running |
| `service stop` | Stops every indexed server, then stops the service |
| `service restart` | Stops the indexed servers, then restarts the service |
| `service enable` | Enables the service so it starts at boot. Does not start servers now |
| `service disable` | Disables the service so it does not start at boot. Does not stop servers that are already running |

## Change a server

| Command | What it does |
| --- | --- |
| `add Ascendra` | Puts that server in the index so it starts with the others |
| `remove Linggango` | Stops it if it is running, then takes it out of the index |
| `rename MonkeyMine MonkeyMine2` | Renames the folder and updates the index if that server was listed |
| `port Cobbleverse 25570` | Sets that server's port in `server.properties` |

`port` works whether or not the server is in the index. The new port is used the next time that server starts.

## Disclaimer

This program was written with help from an AI coding assistant in Cursor. The commands above are what it is meant to do, but AI-written code can still contain mistakes. There may be unforeseen errors and bugs, so double-check anything important, especially starting, stopping, and renaming servers.
