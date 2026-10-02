# modman

`modman` is a small program for managing multiple Minecraft modpacks on a single server. You type commands at a prompt instead of managing the different modpacks by hand.

## Install it

Put this project folder somewhere permanent, for example `~/.local/share/modman`. The `bin`, `tools`, and `data` folders need to stay next to each other. `bin` holds `modman`. The other programs live in `tools`, off your `PATH`.

Make the program executable:

```bash
chmod +x ~/.local/share/modman/bin/modman
```

Add that `bin` folder to your `PATH` so you can run `modman` from any directory. Add this line to `~/.bashrc`:

```bash
export PATH="$HOME/.local/share/modman/bin:$PATH"
```

Then open a new terminal, or run `source ~/.bashrc`, so the change takes effect.

## Configuration

Each modpack is a folder under `/srv/minecraft`. The folder name is the name you type in modman.

`start.sh` has to be in that folder, and it has to be executable. modman runs `./start.sh` from the folder, inside a screen session. That script is what launches the Minecraft server. The mods, the server jar, and `eula.txt` stay in the pack for `start.sh` to use.

`server.properties` holds the port on a `server-port=` line. `list` and `status` show that port, and the `port` command writes it. When the file or the line is missing, the port column shows `-`.

When `start.sh` does not name a `java` program, modman reads `JAVA=` from `variables.txt` and uses that path for the Java version column.

The server creates `logs/latest.log` once it has started. modman reads that log to tell **starting** from **running**.

`data/index.txt` is the list of folder names modman manages together. One name per line. The name must match a folder under `/srv/minecraft`. Blank lines are skipped. Every other line is a server name. The file stays on the machine.

The example looks like this:

```text
Cobbleverse
Ascendra
```

## Start it

Open a terminal and run:

```bash
modman
```

You get a `modman>` prompt. Type a command and press Enter. Type `help` to see the command list again, or `exit` to leave.

The Up and Down arrow keys recall commands you have typed before. Tab finishes a command or a server name.

## Which servers start on boot

Servers listed in `data/index.txt` belong to the boot service (`mc-servers.service`). `start`, `stop`, `restart`, and `status` manage that list as a group. The file format is described under Configuration.

`enable` and `disable` change that list. `disable` stops the server first if it is running, then takes it off the list. The server folder stays on disk.

If you have not already, add boot service `mc-servers.service` to your system using `service install`, and enable it using `service enable`, this allows servers to persist through system reboots.

## See what is going on

| Command | What it shows |
| --- | --- |
| `list` | Displays all modpacks in the /srv/minecraft directory |
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
| `service install` | Installs `mc-servers.service` so it runs as the user who launched modman. Does not enable or start it |

## The control page

`web start` asks for a password, then starts the page. https is on port 8787. http is on port 8788. Put one domain name in `data/.modman-web-domain`. The page answers the signing check on the http port, gets a certificate for that name from Let's Encrypt, and renews it. Other machines open `https://that-name/`. That name has to arrive here on ports 80 and 443. Links that use an address on this machine still use the local certificate. Install that one from `http://<address>:8788/modman-ca.crt` when a browser asks for it. Open a link from another computer and sign in with the password. The page lists every modpack and has buttons for start, stop, restart, enable, disable, the port, the log, install, update, and uninstall. Update still asks whether to keep or delete the world, and deleting the world asks you to type yes.

`web status` prints the link again. `web stop` shuts the page down. `web restart` shuts it down and starts it again, asking for a new password. From the shell, `modman --web start` and `modman -w status` run those same commands without opening the prompt. The actions are start, stop, restart, status, enable, disable, and install. You still type the password to sign in. The browser sends a SHA-256 hash of it, and modman keeps that hash for the run of the page.

`web install` asks for that password, saves the hash, and installs `modman-web.service` to run as the user who launched modman. It does not enable or start the page. `web enable` makes that service start at boot with https and the http fallback. It does not start the page now. `web disable` turns that off and leaves a running page up.

## Open the page from the internet

The page listens on this computer: https on port 8787, http on port 8788. Another network cannot open those ports until something on the public internet delivers port 80 to local port 8788 and port 443 to local port 8787. The bytes have to pass through unchanged. The certificate is created here.

This machine uses [playit.gg](https://playit.gg) for that delivery. A router port forward to a public address works the same way: forward public 80 to 8788 and public 443 to 8787, and point the domain at that public address with an A record.

1. Start the page with `web start`. Use `web install` and `web enable` when it should come back after a reboot.
2. Install the playit agent on this computer and leave it running. The service name is `playit.service`.
3. In the playit account, create two TCP tunnels. One accepts public port 80 and connects to `127.0.0.1:8788`. The other accepts public port 443 and connects to `127.0.0.1:8787`.
4. Add the domain in playit as an external domain. At the DNS host, set a CNAME from that name to the gateway hostname playit shows.
5. Put that domain on one line in `data/.modman-web-domain`.

```text
modman.example.com
```

6. Restart the page if it was already running. It answers Let's Encrypt on port 80, stores the certificate, and renews it while those two tunnels stay up. From another computer, open `https://modman.example.com/` and sign in with the page password.

## Install a modpack

`install` asks for a modpack name, searches CurseForge, and lists the matches. Press Enter to leave the name prompt or the list. Type the number of the one you want. The page has a Clear button beside Search that drops the results. modman downloads that project's server pack and unpacks it under `/srv/minecraft`. The folder name is the modpack name with spaces removed, the same shape as the folders already there. If the pack has no `start.sh`, modman renames `run.sh` (or another launch script) to `start.sh`. When the pack has no launch script, modman writes a `start.sh` that uses the Forge `unix_args.txt` file or the server jar. A pack that only includes a Forge or NeoForge installer gets a `start.sh` that runs that installer, then `run.sh`.

The CurseForge project id, and the server pack file id, are written to `.curseforge-id` in that folder so a later update can tell which project the folder came from.

Put a CurseForge API key on one line in `data/curseforge-api-key`. Create the key at [console.curseforge.com](https://console.curseforge.com). That file stays on this machine.

`install` leaves the new pack out of the index. Use `enable` with the folder name when it should start with the others. If the project has no server pack, install stops.

`update Cobbleverse` installs a newer server pack into a folder that is already there. It asks whether to keep or delete the world. Choosing delete asks you to type yes before the world, `world_nether`, and `world_the_end` are removed. `server.properties`, ops, whitelist, bans, and `eula.txt` stay either way. It then asks you to type yes before the update. A running server is stopped first. When the new pack has no `start.sh`, modman writes one the same way `install` does. If the folder has no `.curseforge-id`, modman searches CurseForge using the folder name. When that search has no matches, it asks for a modpack name and lists results the same way `install` does.

## Change a server

| Command | What it does |
| --- | --- |
| `install` | Searches CurseForge and installs the server pack you pick |
| `update Cobbleverse` | Installs a newer server pack into that folder, after you type yes. Asks whether to keep or delete the world |
| `enable Ascendra` | Puts that server in the index so it starts with the others |
| `disable Linggango` | Stops it if it is running, then takes it out of the index |
| `uninstall Linggango` | Asks you to type yes, then deletes that server folder. Stops it first if it is running, and takes it out of the index if it was listed |
| `rename MonkeyMine MonkeyMine2` | Renames the folder and updates the index if that server was listed |
| `port Cobbleverse 25570` | Sets that server's port in `server.properties` |

`port` works whether or not the server is in the index. The new port is used the next time that server starts.

## Disclaimer

This program was written with help from an AI coding assistant in Cursor. The commands above are what it is meant to do, but AI-written code can still contain mistakes. There may be unforeseen errors and bugs, so double-check anything important, especially starting, stopping, and renaming servers.
