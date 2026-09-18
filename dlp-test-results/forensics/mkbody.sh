#!/bin/sh
out="$1"; names="$2"
jq -c --slurpfile c /tmp/cap/body_cli.json --argjson names "$names" ". + {tools: [\$c[0].tools[] | select(.name as \$n | \$names | index(\$n)) | {type, name, description:\"x\", parameters:{type:\"object\", properties:{}}}], tool_choice: \"auto\"}" /tmp/cap/body_sdk.json > "$out"
