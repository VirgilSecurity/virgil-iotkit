#!/bin/bash

API_URL="https://api-iot.virgilsecurity.com"

function show_help() {
    echo "Usage: $0 [-f tl-file] [-t app-token]"
    echo "-f, --tl-file            path to TrustList file"
    echo "-t, --app-token          Virgil AppToken"
    exit 1
}

# Process options
while [[ "$#" > 0 ]]; do case $1 in
  -f|--tl-file) TL_PATH="$2"; shift;shift;;
  -t|--app-token) APP_TOKEN="$2"; shift;shift;;
*) show_help; shift; shift;;
esac; done

# Upload
echo "Uploading TrustList..."
TL_ID=$( (echo -n '{"body": "'; base64 ${TL_PATH}; echo '"}') |
          curl -H "AppToken: $APP_TOKEN" -d @-  "$API_URL/trustlists" | tee /dev/tty | jq -r '.id')
echo
echo "Uploaded TrustList ID: $TL_ID"

# Publish
echo "Publishing TrustList..."
curl -w "\nStatus code: %{http_code}\n" -H "AppToken: $APP_TOKEN" \
     -d '{"percentage": 100, "devices": []}' "$API_URL/trustlists/$TL_ID/actions/publish"
