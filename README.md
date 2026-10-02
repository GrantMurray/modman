# modman

modman manages several Minecraft modpacks on one computer. You run it from a prompt and type commands.

## Install it

Put this project folder somewhere permanent. The `bin`, `tools`, and `data` folders need to stay next to each other. `bin` holds `modman`. The other programs live in `tools`, off your `PATH`.

This example uses `~/.local/share/modman`. Use the path you actually chose.

Make the program executable:

```bash
chmod +x ~/.local/share/modman/bin/modman
```

Add that `bin` folder to your `PATH` so you can run `modman` from any directory. Add this line to `~/.bashrc`:

```bash
export PATH="$HOME/.local/share/modman/bin:$PATH"
```

Open a new terminal, or run `source ~/.bashrc`, so the change takes effect.

## Configuration

Each modpack is a folder under `/srv/minecraft`. The folder name is the name you type in modman.

`start.sh` has to be in that folder, and it has to be executable. modman runs `./start.sh` from the folder, inside a screen session. That script launches the Minecraft server. The mods, the server jar, and `eula.txt` stay in the pack for `start.sh` to use.

`server.properties` holds the port on a `server-port=` line. `list` and `status` show that port, and the `port` command writes it. When the file or the line is missing, the port column shows `-`.

When `start.sh` does not name a `java` program, modman reads `JAVA=` from `variables.txt` and uses that path for the Java version column.

The server creates `logs/latest.log` once it has started. modman reads that log to tell **starting** from **running**.

`data/index.txt` is the list of folder names modman manages together. One name per line. The name must match a folder under `/srv/minecraft`. Blank lines are skipped. The file stays on the computer where modman runs.

```text
MyPack
AnotherPack
```

## Start it

Open a terminal and run:

```bash
modman
```

You get a `modman>` prompt. Type a command and press Enter. Type `help` to see the command list again, or `exit` to leave.

The Up and Down arrow keys recall commands you have typed before. Tab finishes a command or a server name.

## Which servers start on boot

Servers listed in `data/index.txt` belong to the boot service (`mc-servers.service`). `start`, `stop`, `restart`, and `status` manage that list as a group.

`enable` and `disable` change that list. `disable` stops the server first if it is running, then takes it off the list. The server folder stays on disk.

Run `service install`, then `service enable`, so those servers start again after a reboot.

## See what is going on

| Command | What it shows |
| --- | --- |
| `list` | Every modpack folder under `/srv/minecraft` |
| `status` | Running or stopped, for every indexed server |
| `status MyPack` | That view for one server |
| `usage` | CPU, memory, and uptime for each indexed server |
| `usage MyPack` | Those numbers for one server |

A server that is not running shows `-` for CPU, memory, and uptime.

- **stopped** means there is no live screen session.
- **starting** means the screen is up, and the server has not printed that it is done loading yet.
- **running** means startup has finished.

If two servers use the same port, their names show up highlighted. They will not both start properly until the ports differ.

## Start, stop, and watch a server

| Command | What it does |
| --- | --- |
| `start` | Starts every indexed server that is not already running |
| `start MyPack` | Starts that server |
| `stop` | Stops every indexed server |
| `stop MyPack` | Stops that server |
| `restart` | Stops and starts every indexed server |
| `restart MyPack` | Stops and starts that server |
| `join MyPack` | Opens that server's live console |

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

`web start` asks for a password, then starts the page. https is on port 8787. http is on port 8788. The page lists every modpack and has buttons for start, stop, restart, enable, disable, the port, the log, install, update, and uninstall.

Update still asks whether to keep or delete the world. Choosing delete asks you to type yes. The browser sends a SHA-256 hash of the password, and modman keeps that hash.

On the same network, open an address link that `web start` prints. The browser will ask you to trust a certificate from this computer. You can install that certificate from `http://<address>:8788/modman-ca.crt`.

From anywhere else, use a domain name. Put that name on one line in `data/.modman-web-domain`. The page gets a certificate for it from Let's Encrypt and renews it. See the next section for how the name has to reach this computer.

| Command | What it does |
| --- | --- |
| `web start` | Asks for a password, then starts the page |
| `web stop` | Shuts the page down |
| `web reset` | Shuts the page down and starts it again, asking for a new password |
| `web status` | Prints the link again |
| `web install` | Saves the password hash and installs `modman-web.service`. Does not enable or start the page |
| `web enable` | Starts the page at boot. Does not start it now |
| `web disable` | Stops the page from starting at boot. Leaves a running page up |

From the shell, `modman --web start` and `modman -w status` run one of those commands and then exit. The actions are start, stop, reset, status, enable, disable, and install.

## Open the page from the internet

People off the local network open the page with a domain name, for example `https://modman.example.com/`. Two public ports have to reach the computer where modman runs:

- Public port 80 connects to local port 8788.
- Public port 443 connects to local port 8787.

The connection has to pass through unchanged. The certificate is created on the modman computer, and Let's Encrypt checks the name through port 80.

**On a router.** Forward public port 80 to local port 8788, and public port 443 to local port 8787. Point the domain at that public address with an A record.

**Through a tunnel.** Use this when the computer has no public address. Any TCP tunnel works. [playit.gg](https://playit.gg) is one. Create two TCP tunnels, one from public port 80 to `127.0.0.1:8788` and one from public port 443 to `127.0.0.1:8787`. Point the domain at the tunnel with the CNAME that service gives you, and leave the tunnel program running.

Then:

1. Put the domain on one line in `data/.modman-web-domain`.
2. Start the page with `web start`. If it is already running, run `web reset`.
3. Open `https://modman.example.com/` from another computer and sign in.

Use `web install` and `web enable` when the page should start again after a reboot. The tunnel program has to start on boot as well, or the name will not reach the page.

## Install a modpack

Put a CurseForge API key on one line in `data/curseforge-api-key`. Create the key at [console.curseforge.com](https://console.curseforge.com). That file stays on the computer where modman runs.

`install` asks for a modpack name, searches CurseForge, and lists the matches. Press Enter to leave the name prompt or the list. Type the number of the one you want. On the page, Clear beside Search drops the results.

modman downloads that project's server pack and unpacks it under `/srv/minecraft`. The folder name is the modpack name with spaces removed. The new pack is left out of the index. Run `enable` with the folder name when it should start with the others. If the project has no server pack, install stops.

If the pack has no `start.sh`, modman renames `run.sh` (or another launch script) to `start.sh`. When the pack has no launch script, modman writes a `start.sh` that uses the Forge `unix_args.txt` file or the server jar. A pack that only includes a Forge or NeoForge installer gets a `start.sh` that runs that installer, then `run.sh`.

The CurseForge project id, and the server pack file id, are written to `.curseforge-id` in that folder so a later update can tell which project the folder came from.

`update MyPack` installs a newer server pack into a folder that is already there. It asks whether to keep or delete the world. Choosing delete asks you to type yes before the world, `world_nether`, and `world_the_end` are removed. `server.properties`, ops, whitelist, bans, and `eula.txt` stay either way. It then asks you to type yes before the update. A running server is stopped first. When the new pack has no `start.sh`, modman writes one the same way `install` does. If the folder has no `.curseforge-id`, modman searches CurseForge using the folder name. When that search has no matches, it asks for a modpack name and lists results the same way `install` does.

## Change a server

| Command | What it does |
| --- | --- |
| `install` | Searches CurseForge and installs the server pack you pick |
| `update MyPack` | Installs a newer server pack into that folder, after you type yes. Asks whether to keep or delete the world |
| `enable MyPack` | Puts that server in the index so it starts with the others |
| `disable MyPack` | Stops it if it is running, then takes it out of the index |
| `uninstall MyPack` | Asks you to type yes, then deletes that server folder. Stops it first if it is running, and takes it out of the index if it was listed |
| `rename MyPack MyPack2` | Renames the folder and updates the index if that server was listed |
| `port MyPack 25570` | Sets that server's port in `server.properties` |

`port` works whether or not the server is in the index. The new port is used the next time that server starts.

## Disclaimer

This program was written with help from an AI coding assistant in Cursor. The commands above are what it is meant to do, but AI-written code can still contain mistakes. There may be unforeseen errors and bugs, so double-check anything important, especially starting, stopping, and renaming servers.
