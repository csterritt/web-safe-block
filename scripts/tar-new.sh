#!/usr/bin/env bash
# tar-new.sh: archive every path `git status` reports as added, modified,
# renamed-to, copied-to, or otherwise changed, and write the paths it
# reports as deleted to <archive>.deleted.
# Usage: tar-new.sh <archive-name>

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <archive-name>" >&2
  exit 1
fi

archive="$1"
deleted_list="$archive.deleted"

files=()
deleted=()

# Porcelain -z: two status columns, then the path (and a second path for
# renames/copies). Renames archive the new path and list the old as deleted.
while IFS= read -r -d '' entry; do
  x="${entry:0:1}"
  y="${entry:1:1}"
  path="${entry:3}"
  case "$x$y" in
    R*|C*)
      # Next NUL-separated record is the old path.
      IFS= read -r -d '' old_path || old_path=""
      files+=("$path")
      if [[ "$x" == "R" || "$y" == "R" ]]; then
        deleted+=("$old_path")
      fi
      ;;
    *)
      if [[ "$x" == "D" || "$y" == "D" ]]; then
        deleted+=("$path")
      else
        files+=("$path")
      fi
      ;;
  esac
done < <(git status --porcelain=v1 -z --untracked-files=all)

if [[ ${#deleted[@]} -gt 0 ]]; then
  printf '%s\0' "${deleted[@]}" > "$deleted_list"
else
  : > "$deleted_list"
fi

if [[ ${#files[@]} -gt 0 ]]; then
  printf '%s\0' "${files[@]}" | tar -cf "$archive" --null -T -
else
  # Always create the archive, even when empty.
  tar -cf "$archive" -T /dev/null
fi

echo "Archived ${#files[@]} file(s), ${#deleted[@]} deletion(s) -> $archive"
