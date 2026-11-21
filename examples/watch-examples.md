# Watch examples

```sh
# Default: start at EOF; restore checkpoint when available.
webaudit watch /var/log/nginx/access.log

# Replay all input intentionally, then follow. This resets revisions/notifications.
webaudit watch access.log --reset-state --from beginning --format jsonl

# No checkpoint, two explicit files, out-of-order tolerance of two minutes.
webaudit watch access.log site_access.log --no-state --allowed-lateness 2m

# Nonrecursive directory selection; error.log excluded by default.
webaudit watch /var/log/nginx/ --include '*access*.log' --exclude '*private*'

# notify.sh requires Python 3; it prints a safe JSON summary (no external send).
chmod +x examples/notify.sh
webaudit watch access.log --on-detect ./examples/notify.sh

# Also notify significant updates; repeat --on-detect for a second executable.
webaudit watch access.log --on-detect ./examples/notify.sh \
  --on-detect-event all --on-detect-severity high --hook-timeout 5s \
  --hook-concurrency 2 --hook-queue-size 64
```

```powershell
.\webaudit.exe watch .\access.log --on-detect powershell.exe `
  --on-detect-arg=-NoProfile --on-detect-arg=-File `
  --on-detect-arg=examples/notify.ps1
```

Hook stdout is bounded and not displayed by WebAudit. These examples validate and
summarize JSON; adapt them to your explicitly selected notification destination.
Never use eval, Invoke-Expression or command interpolation with event fields.
Executable paths and each argument are separate CLI values; quotes are handled by
the invoking terminal, not by a shell inside WebAudit.

Full schema, checkpoint semantics and limits: [watch guide](../docs/watch.md).
