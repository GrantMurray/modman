#!/usr/bin/env bash
# Started by mc-servers.service. Launches each indexed modpack that is not
# already running. Paths are filled in by `service install`.
INDEX_FILE="__INDEX_FILE__"
MINECRAFT_ROOT="__MINECRAFT_ROOT__"

if [[ ! -f "$INDEX_FILE" ]]; then
	echo "Index not found: $INDEX_FILE" >&2
	exit 1
fi

mapfile -t servers < <(grep -v '^[[:space:]]*$' "$INDEX_FILE" || true)

for server_name in "${servers[@]}"; do
	if ! screen -list | grep -q "mc-${server_name}"; then
		echo "Starting screen/server mc-${server_name}..."
		screen -dmS "mc-${server_name}" bash -c "cd \"${MINECRAFT_ROOT}/${server_name}\" && ./start.sh"
	fi
done
