#!/bin/sh
SHELLCHECK_ARGS="${SHELLCHECK_ARGS:-"--exclude=SC2086 --exclude=SC2129"}"
find .github -name '*.yaml' -print0 \
    | xargs -0 yq '(.runs.steps // [])[] | .run // ""' \
    | while read -r script; do
        printf "%s" "$script" \
            | jq -r . \
            | shellcheck --norc --shell=bash $SHELLCHECK_ARGS -
done
