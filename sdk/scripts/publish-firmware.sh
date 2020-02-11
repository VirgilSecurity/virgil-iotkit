#!/bin/bash

API_URL="https://api-iot.virgilsecurity.com"

function show_help() {
    echo "Usage: $0 [-f update-file] [-t app-token]"
    echo "-f, --update-file        path to firmware *_Update file"
    echo "-t, --app-token          Virgil AppToken"
    exit 1
}

# Process options
while [[ "$#" > 0 ]]; do case $1 in
  -f|--update-file) FW_PATH="$2"; shift;shift;;
  -t|--app-token) APP_TOKEN="$2"; shift;shift;;
*) show_help; shift; shift;;
esac; done

# Upload
echo "Uploading Firmware..."
FW_ID=$( (echo -n '{"body": "'; base64 ${FW_PATH}; echo '"}') |
          curl -H "AppToken: $APP_TOKEN" -d @-  "$API_URL/firmwares" | tee /dev/tty | jq -r '.id')
echo
echo "Uploaded Firmware ID: $FW_ID"

# Publish
echo "Publishing Firmware..."
curl -w "\nStatus code: %{http_code}\n" -H "AppToken: $APP_TOKEN" \
     -d '{"percentage": 100, "devices": []}' "$API_URL/firmwares/$FW_ID/actions/publish"
