# modman

modman manages several Minecraft modpack servers on one Linux computer. You run it from a prompt and type commands. It can:

- install and update server packs from CurseForge
- start, stop, and restart each server in its own `screen` session
- start a chosen set of servers when the computer boots
- show status, CPU, memory, uptime, and port conflicts
- serve a password-protected control page you can open from a phone or another computer

## Requirements

- Linux with systemd. These steps use Debian or Ubuntu commands.
- bash, `screen`, Python 3.7 or newer, `curl`, `openssl`, and `sudo`.
- Java for the servers. The version depends on the Minecraft version of each pack:

  | Minecraft | Java |
  | --- | --- |
  | 1.16.5 and older | 8 |
  | 1.18 to 1.20.4 | 17 |
  | 1.20.5 to 1.21.x | 21 |

  For newer versions, check the pack's page for the Java it needs.
- A CurseForge API key, only if you want `install` and `update`.

## Set it up from scratch

### 1. Install the dependencies

```bash
sudo apt update
sudo apt install -y git screen python3 curl openssl ca-certificates sudo openjdk-21-jre-headless
```

If your distribution does not package the Java version a pack needs (Debian 13 has no Java 17, for example), install it from [Adoptium](https://adoptium.net):

```bash
sudo apt install -y wget gpg
wget -qO - https://packages.adoptium.net/artifactory/api/gpg/key/public | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/adoptium.gpg >/dev/null
echo "deb https://packages.adoptium.net/artifactory/deb $(awk -F= '/^VERSION_CODENAME/{print $2}' /etc/os-release) main" | sudo tee /etc/apt/sources.list.d/adoptium.list
sudo apt update
sudo apt install -y temurin-17-jre
```

Check what is installed with `java -version`. When several are installed, a pack's `start.sh` can name one by full path, for example `/usr/lib/jvm/temurin-17-jre-amd64/bin/java`.

### 2. Get modman

```bash
git clone https://github.com/GrantMurray/modman.git ~/.local/share/modman
chmod +x ~/.local/share/modman/bin/modman
echo 'export PATH="$HOME/.local/share/modman/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

The `bin`, `tools`, and `data` folders have to stay next to each other. Another location works too; change the paths above to match.

### 3. Make the folder for the servers

Every modpack lives in its own folder under `/srv/minecraft`, owned by the account that runs modman:

```bash
sudo mkdir -p /srv/minecraft
sudo chown "$USER": /srv/minecraft
```

### 4. Add a CurseForge API key (optional)

Create a key at [console.curseforge.com](https://console.curseforge.com), then save it on one line:

```bash
nano ~/.local/share/modman/data/curseforge-api-key
chmod 600 ~/.local/share/modman/data/curseforge-api-key
```

Skip this step if you only use packs you copy into `/srv/minecraft` yourself.

### 5. Install and start a first server

Start modman:

```bash
modman
```

At the `modman>` prompt, run `install`, search for a modpack, and pick a number from the list. The pack goes into `/srv/minecraft/<PackName>`, with spaces removed from the name.

Then enable and start it, using the folder name `install` printed:

```text
enable MyPack
start MyPack
status
```

Minecraft will not start until you accept its [EULA](https://aka.ms/MinecraftEULA). The first `start` shows the link and asks you to type yes, then writes `eula=true` to the pack's `eula.txt` for you. The control page asks the same with an **I agree** button. The boot service cannot ask, so it skips a pack whose EULA has not been accepted; start that pack once from the prompt or the page first.

`status` shows **starting** while the server loads, then **running**. `join MyPack` opens its console; press **Ctrl-A**, then **d**, to leave it running.

Players connect on port 25565 unless you change it with `port MyPack 25570`. Each server needs its own port. If the computer has a firewall, open that port, for example `sudo ufw allow 25565/tcp`.

### 6. Start servers at boot (optional)

At the `modman>` prompt:

```text
service install
service enable
```

Every server you have run `enable` on starts after a reboot. The install step asks for your sudo password.

### 7. Turn on the control page (optional)

The page needs the user service manager running even when nobody is logged in:

```bash
sudo loginctl enable-linger "$USER"
```

At the `modman>` prompt:

```text
web install
web enable
web start
```

`web install` asks for the page password. `web start` prints the links to open and the fingerprint of the page's certificate. To reach the page from outside your network, see [Open the page from the internet](#open-the-page-from-the-internet).

## How modman finds servers

Each modpack is a folder under `/srv/minecraft`. The folder name is the name you type in modman. To add a pack you set up by hand, copy its server files into a new folder there.

`start.sh` has to be in that folder, and it has to be executable. modman runs `./start.sh` from the folder, inside a screen session. That script launches the Minecraft server. The mods, the server jar, and `eula.txt` stay in the pack for `start.sh` to use.

Each server runs in a sandbox, because `start.sh` and the jars come from whoever made the pack. The server can write only its own folder. It cannot see your home folder (modman, its passwords, the CurseForge key) or any other pack, the rest of the system is read-only, and `sudo` does not work. So `start.sh` and Java have to live outside `/home`, for example Java under `/usr/lib/jvm`.

`server.properties` holds the port on a `server-port=` line. `list` and `status` show that port, and the `port` command writes it. When the file or the line is missing, the port column shows `-`.

`edit MyPack` lists every value in `server.properties` with a number. Type a number or a property name, then the new value. Settings that are true or false only take true or false, and whole-number settings only take whole numbers. Only existing settings can be changed, and the file is only there after the server has started once. A running server picks up the change after a restart. On the webpage, **Properties…** in each server's **⋯** menu does the same.

When `start.sh` does not name a `java` program, modman reads `JAVA=` from `variables.txt` and uses that path for the Java version column.

`java MyPack` shows which Java the pack runs and which one its Minecraft version needs, then lists the installed Javas to pick from. Choosing one rewrites every `java` command in `start.sh` and in Forge's `run.sh`, and the `JAVA=` line in `variables.txt`. Only Javas root installed under `/usr/lib/jvm`, or the system `java`, can be chosen. A running server picks up the change when it restarts.

The server creates `logs/latest.log` once it has started. modman reads that log to tell **starting**, **running**, and **error** apart. Right after a start, the log left from the last run is ignored until the new server writes to it, so a server shows **starting** rather than **running** while it loads.

`data/index.txt` is the list of folder names modman manages together. One name per line. The name must match a folder under `/srv/minecraft`. Blank lines are skipped. `enable` and `disable` edit this file for you.

```text
MyPack
AnotherPack
```

## Using the prompt

You get a `modman>` prompt. Type a command and press Enter. Type `help` to see the command list again, or `exit` to leave.

The Up and Down arrow keys recall commands you have typed before. Tab finishes a command or a server name.

## Which servers start on boot

Servers listed in `data/index.txt` belong to the boot service (`mc-servers.service`). `start`, `stop`, `restart`, and `status` manage that list as a group.

`enable` and `disable` change that list. `disable` stops the server first if it is running, then takes it off the list. The server folder stays on disk.

Run `service install`, then `service enable`, so those servers start again after a reboot. The service runs modman from its folder (`modman --boot`), so later changes to modman apply without installing again. Run `service install` again if you move the modman folder, or if you installed the service before this version, which used a copied helper in `/usr/local/bin`.

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
- **error** means the screen is still open, and the server has crashed or hit an error.

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

`start MyPack`, `stop MyPack`, and `restart MyPack` work for a server that is not enabled. That is there so you can try one without putting it in the boot list. The control page offers them only for an enabled server.

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

`web start` starts the page with the saved password. https is on port 8787. http on port 8788 only hands out the certificate, answers Let's Encrypt, and sends everything else to https.

The page lists every modpack in two groups. **Active** holds the enabled servers, with their status, CPU, memory, and uptime. **Installed** holds the rest. Click the Installed heading to fold that list away. It starts folded on a phone, and the page remembers your choice in that browser.

Each server has one main button for what you most likely want next: **Start** for a stopped server, **Stop** for a running one, **Restart** for one that hit an error, and **Enable** for an installed one. Beside it, **Log** shows that server's console, and **⋯** opens the rest: Restart, Properties… for `server.properties`, Change port…, Version…, Java…, Update…, Disable, and Uninstall…. A server's details line shows its version when one is known. Version… shows what modman saved about the installed pack (version, source, link or file, install time, and SHA-256) and lets you type a different version. Java… does what `java MyPack` does: it lists the installed Javas, marks the one the server runs and any that do not suit its Minecraft version, and saves the one you pick. Start, stop, and restart are only offered for enabled servers, so a one-off test of an installed server is done from the prompt. A server started from the page runs in your user service, so restarting the page leaves it running.

The result of an action, such as stopping a modpack, shows as a note in the bottom corner. A note for an action that worked fades after a few seconds. An error stays until you close it. **Install modpack** opens a CurseForge search in its own window.

The console list has Actions plus each running server, and a server console keeps updating. Warnings show in yellow and errors in red. The command box sends one line to the selected server, and the Up and Down arrow keys bring back commands sent before from that browser. If you scroll up to read, new lines do not pull you back down; **↓ Latest** jumps to the end. Pressing **Log** on a stopped server shows the last log it wrote. On a wide screen the console sits beside the server list.

The header shows whether the boot service is running and whether it starts at boot. The **Service** menu controls it. **Menu** has **Unlock page**, which cancels anything the page is waiting on and turns greyed-out buttons back on, and **Sign out**. The page follows the light or dark setting of your device.

Update can use CurseForge or a download link, and still asks whether to keep or delete the world. Choosing delete asks you to type yes.

The password has to be at least 4 characters. modman keeps a salted scrypt hash of it, never the password. A password saved by an older modman still works, but `web start` warns until you run `web password` again. One address gets 10 wrong passwords every 15 minutes. Behind a tunnel every visitor shares the tunnel's address, so wrong guesses from anyone can lock the page for 15 minutes. A sign-in lasts 7 days, or 12 hours without use.

On the same network, open an address link that `web start` prints. The browser will ask you to trust a certificate from this computer. You can install that certificate from `http://<address>:8788/modman-ca.crt`. `web start` prints its SHA-256 fingerprint; check that it matches before trusting it. The certificate can only vouch for local network addresses and names such as `.local` and `.lan`, so it cannot be used to fake other sites.

From anywhere else, use a domain name. Put that name on one line in `data/.modman-web-domain`. The page gets a certificate for it from Let's Encrypt and renews it. See the next section for how the name has to reach this computer.

| Command | What it does |
| --- | --- |
| `web start` | Starts the page with the saved password |
| `web stop` | Shuts the page down |
| `web restart` | Shuts the page down and starts it again |
| `web status` | Prints the link again |
| `web password` | Sets or changes the webpage password. `web pswd` does the same |
| `web admin` | Sets or changes the admin password for blacklisted console commands |
| `web viewer` | Sets or changes a view-only password for the page |
| `web install` | Asks for a password, saves the hash, and installs `modman-web.service`. Does not enable or start the page |
| `web enable` | Starts the page at boot with the saved password. Does not start it now |
| `web disable` | Stops the page from starting at boot. Leaves a running page up |

From the shell, `modman --web start` and `modman -w status` run one of those commands and then exit. The actions are start, stop, restart, status, password, admin, viewer, enable, disable, and install. `web password` restarts a running page so the new password is the one that signs in.

### View-only sign-in

`web viewer` sets a second password for the page. Signing in with it shows the server list, status, usage, and the consoles, with a **View only** tag in the header. The buttons that change anything are hidden: Start, Stop, the **⋯** menu, **Install modpack**, the **Service** menu, and the console command box. **Log** still works. The page refuses those actions from a view-only sign-in even if a request is sent another way.

The page reads the view-only password at each sign-in, so it needs no restart. Running `web viewer` again signs out everyone who used the old one. To turn view-only sign-in off, delete `data/.modman-web-view-hash`; that also signs out every view-only sign-in. Wrong passwords count toward the same limit whichever password was meant.

### Blacklisted console commands

`data/blacklist.txt` lists console commands the page will only send with an admin password. That password is separate from the page password, so someone who can sign in still cannot stop a server or op a player from the console without it. Set it with `web admin`.

Start from the example:

```bash
cp ~/.local/share/modman/data/blacklist.txt.example ~/.local/share/modman/data/blacklist.txt
```

Put one command per line. A line matches any command that starts with its words, so `gamerule keepInventory` blocks that rule and leaves other gamerules alone, and `stop` does not block `stopwatch`. Case, a leading `/`, and a namespace such as `minecraft:` are ignored. The command after each `run` in an `execute` command is checked too. Anything after `#` is a comment.

When a command on the list is sent, the page asks for the admin password and sends it with that one command only. Wrong admin passwords count toward the same 10-per-15-minutes limit as sign-ins. If the list has commands but no admin password is set, those commands are refused. The page reads the list and the password each time, so changes apply without a restart.

The blacklist only covers the page's console box. `join` at the `modman>` prompt is a direct console and is not limited.

## Open the page from the internet

People off the local network open the page with a domain name, for example `https://modman.example.com/`. Two public ports have to reach the computer where modman runs:

- Public port 80 connects to local port 8788.
- Public port 443 connects to local port 8787.

The connection has to pass through unchanged. The certificate is created on the modman computer, and Let's Encrypt checks the name through port 80.

**On a router.** Forward public port 80 to local port 8788, and public port 443 to local port 8787. Point the domain at that public address with an A record.

**Through a tunnel.** Use this when the computer has no public address. Any TCP tunnel works. [playit.gg](https://playit.gg) is one. Create two TCP tunnels, one from public port 80 to `127.0.0.1:8788` and one from public port 443 to `127.0.0.1:8787`. Point the domain at the tunnel with the CNAME that service gives you, and leave the tunnel program running.

Then:

1. Put the domain on one line in `data/.modman-web-domain`.
2. Start the page with `web start`. If it is already running, run `web restart`.
3. Open `https://modman.example.com/` from another computer and sign in.

Use `web install` and `web enable` when the page should start again after a reboot. The tunnel program has to start on boot as well, or the name will not reach the page.

## Install a modpack

`install` and `update` need a CurseForge API key in `data/curseforge-api-key` (see [step 4](#4-add-a-curseforge-api-key-optional)). That file stays on the computer where modman runs.

`install` asks for a modpack name, searches CurseForge, and lists the matches. Press Enter to leave the name prompt or the list. Type the number of the one you want. On the page, **Install modpack** opens the search, and clicking a result asks before it installs.

modman downloads that project's server pack and unpacks it under `/srv/minecraft`. The folder name is the modpack name with spaces removed. The new pack is left out of the index. Run `enable` with the folder name when it should start with the others. If the project has no server pack, install stops.

If the pack has no `start.sh`, modman renames `run.sh` (or another launch script) to `start.sh`. When the pack has no launch script, modman writes a `start.sh` that uses the Forge `unix_args.txt` file or the server jar. A pack that only includes a Forge or NeoForge installer gets a `start.sh` that runs that installer, then `run.sh`.

The CurseForge project id, and the server pack file id, are written to `.curseforge-id` in that folder so a later update can tell which project the folder came from.

Each install and update also writes `.modman-version` in the folder, with the pack's version, where it came from (CurseForge, a link, or a zip), when it was installed, and for a link or zip the file's SHA-256. modman guesses the version from, in order: the CurseForge release name, the pack's own `config/bcc-common.toml` or `config/bcc.json`, its `manifest.json`, then a version number in the download's file name or the link. A number that only looks like a Minecraft version, such as 1.20.1, is skipped. When nothing fits, the version is unknown. `version MyPack 2.5.0` types it by hand, and the next install or update replaces it. `version` lists every pack's version, and `version MyPack` shows one pack's details.

`update MyPack` installs a newer server pack into a folder that is already there. It first asks where the pack comes from: CurseForge (the default, press Enter), a download link such as Google Drive, OneDrive, or Dropbox, or a local zip file. A link must be shared so anyone with it can view the file, and must point at the zip, not a folder. Updating from a link or zip removes `.curseforge-id`, so a later CurseForge update searches for the project again. The webpage's **Update…** offers CurseForge or a download link. A link from the webpage must point at a public site; links to this machine or the local network are refused, including through redirects. Downloads over 2 GB, or zips that unpack to over 4 GB or hold over 100,000 files, are refused. It then asks whether to keep or delete the world. Choosing delete asks you to type yes before the world, `world_nether`, and `world_the_end` are removed. `server.properties`, ops, whitelist, bans, and `eula.txt` stay either way. It then asks you to type yes before the update. A running server is stopped first. When the new pack has no `start.sh`, modman writes one the same way `install` does. For a CurseForge update, if the folder has no `.curseforge-id`, modman searches CurseForge using the folder name. When that search has no matches, it asks for a modpack name and lists results the same way `install` does.

## Change a server

| Command | What it does |
| --- | --- |
| `install` | Searches CurseForge and installs the server pack you pick |
| `update MyPack` | Installs a newer server pack from CurseForge, a download link, or a local zip into that folder, after you type yes. Asks whether to keep or delete the world |
| `enable MyPack` | Puts that server in the index so it starts with the others |
| `disable MyPack` | Stops it if it is running, then takes it out of the index |
| `uninstall MyPack` | Asks you to type yes, then deletes that server folder. Stops it first if it is running, and takes it out of the index if it was listed |
| `rename MyPack MyPack2` | Renames the folder and updates the index if that server was listed |
| `port MyPack 25570` | Sets that server's port in `server.properties` |
| `version` / `version MyPack` / `version MyPack 2.5.0` | Lists every pack's version, shows one pack's details, or types a pack's version by hand |
| `java` / `java MyPack` / `java MyPack 3` | Lists the Javas installed in `/usr/lib/jvm`, or shows which one a pack runs and lets you pick another by number, by path, or `default` for the system's `java` |

`port` works whether or not the server is in the index. The new port is used the next time that server starts.

## Disclaimer

This program was written with help from an AI coding assistant in Cursor. The commands above are what it is meant to do, but AI-written code can still contain mistakes. There may be unforeseen errors and bugs, so double-check anything important, especially starting, stopping, and renaming servers.
