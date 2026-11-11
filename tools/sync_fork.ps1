# Keep ng643/PS5-14.10-Research level with ZigZagBoi1/PS5-14.10-Research.
#
# The fork also carries .github/workflows/sync-fork.yml, which does this daily on its
# own - but GitHub leaves Actions disabled on forks until they are enabled once in
# the web UI (Settings -> Actions -> General -> Allow all actions). Until that click
# happens, this script is the manual equivalent.
#
#   powershell -File tools\sync_fork.ps1
#
# Both branches the upstream repo uses are synced; failures are reported, not fatal.

$ErrorActionPreference = 'Stop'
$fork = 'ng643/PS5-14.10-Research'
$upstream = 'ZigZagBoi1/PS5-14.10-Research'

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw 'gh (GitHub CLI) is not on PATH'
}

foreach ($branch in @('master', 'main')) {
    $before = gh api "repos/$fork/branches/$branch" --jq .commit.sha 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "$branch : missing on fork, skipping"
        continue
    }

    $upBefore = gh api "repos/$upstream/branches/$branch" --jq .commit.sha 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "$branch : missing upstream, skipping"
        continue
    }

    if ($before -eq $upBefore) {
        Write-Host "$branch : up to date at $($before.Substring(0,8))"
        continue
    }

    gh repo sync $fork --source $upstream --branch $branch | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "$branch : sync FAILED - resolve manually (git fetch upstream; git merge)"
        continue
    }

    $after = gh api "repos/$fork/branches/$branch" --jq .commit.sha
    if ($after -eq $upBefore) {
        Write-Host "$branch : synced $($before.Substring(0,8)) -> $($after.Substring(0,8))"
        continue
    }
    $status = gh api "repos/$fork/compare/$($upBefore)...$($after)" --jq .status
    $ahead = gh api "repos/$fork/compare/$($upBefore)...$($after)" --jq .ahead_by
    if ($status -eq 'ahead') {
        Write-Host "$branch : upstream merged, fork ahead by $ahead local commit(s) at $($after.Substring(0,8))"
    } else {
        Write-Host "$branch : now at $($after.Substring(0,8)), upstream at $($upBefore.Substring(0,8)) - check manually"
    }
}
