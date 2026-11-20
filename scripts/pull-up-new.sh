#!/usr/bin/env bash

set -euo pipefail

force=0
for arg in "$@"; do
  if [ "$arg" = '--force' ]; then
    force=1
  fi
done

if [ "$force" -ne 1 ]; then
  jj_status=$(jj st 2>&1)
  if ! echo "$jj_status" | grep -q 'The working copy has no changes.'; then
    echo "The working copy has changes. Use --force to proceed anyway." >&2
    exit 1
  fi
fi

last_dir=$(basename "$(pwd)")

remote_dir=$(ssh chris@utmbox mktemp -d)
local_dir=$(mktemp -d)
trap 'rm -rf "$local_dir"' EXIT

ssh chris@utmbox "cd $(printf %q "$last_dir") && scripts/tar-new.sh $(printf %q "$remote_dir")/new-files.tar"

scp -q "chris@utmbox:$remote_dir/new-files.tar" "$local_dir/new-files.tar"
scp -q "chris@utmbox:$remote_dir/new-files.tar.deleted" "$local_dir/new-files.tar.deleted"

tar xf "$local_dir/new-files.tar"

while IFS= read -r -d '' file; do
  [ -n "$file" ] && rm -f "$file"
done < "$local_dir/new-files.tar.deleted"

ssh chris@utmbox "rm -rf $(printf %q "$remote_dir")"
