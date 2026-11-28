#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

readonly gitlink_mode=160000
readonly git_sha1_hex_chars=40

if (( $# < 6 )); then
  echo 'Usage: scout-package-review.sh SCOUT PROVIDER PROJECT BASE_SHA HEAD_SHA PACKAGE_PATH [report options]' >&2
  exit 2
fi

scout=$1 provider=$2 project=$3 base=$4 head=$5 package=$6
shift 6

is_sha() {
  [[ ${#1} -eq git_sha1_hex_chars && "$1" != *[!0-9a-f]* ]]
}

if ! is_sha "$base" || ! is_sha "$head" || [[ -z "$package" || "$package" == *[!A-Za-z0-9._/-]* ]]; then
  echo 'Expected two full commit SHAs and a repository-relative package directory.' >&2
  exit 2
fi

work=$(mktemp -d)
work=$(realpath -- "$work")
cleanup() {
  git worktree remove --force "$work/before" 2>/dev/null || true
  git worktree remove --force "$work/candidate" 2>/dev/null || true
  rm -rf -- "$work"
}
trap cleanup EXIT

stage_package() {
  local revision=$1 tree=$2 input="$work/$2/$package"
  local modes
  if ! git cat-file -e "$revision^{commit}" 2>/dev/null; then
    git fetch --depth=1 --no-tags origin "$revision" >&2
  fi
  git -c core.hooksPath=/dev/null worktree add --detach "$work/$tree" "$revision" >&2
  if [[ ! -d "$input" || "$(realpath -- "$input")" != "$input" ]]; then
    echo 'The package must be a real directory in both revisions.' >&2
    exit 2
  fi
  modes=$(git ls-tree -r --format='%(objectmode)' "$revision" -- "$package")
  if [[ $'\n'"$modes"$'\n' == *$'\n'"$gitlink_mode"$'\n'* ]]; then
    echo 'The package must not contain Git submodules.' >&2
    exit 2
  fi
}

stage_package "$base" before
stage_package "$head" candidate

approval=()
if [[ -n "${SCOUT_APPROVED_SHA256:-}" ]]; then
  approval=(--approved-sha256 "$SCOUT_APPROVED_SHA256")
fi

"$scout" compare --pr-provider "$provider" --pr-head "$project@$head" --pr-path "$package" \
  "${approval[@]}" "$@" -- "$work/before/$package" "$work/candidate/$package"
