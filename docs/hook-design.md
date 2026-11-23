# Hook design

Repeated --on-detect specifies executable paths. --on-detect-arg appends a literal
argument to the preceding hook; no shell splitting, substitution or template expansion.
Arguments and executable come exclusively from CLI configuration. Defaults: high,
created, 10 seconds, one worker; queue and output are bounded. Dispatcher workers
use exec.CommandContext, JSON stdin and bounded stdout/stderr capture. Failures,
timeouts and dropped notifications go to stderr, never interrupt log monitoring.

Hook payload is the redacted incident event plus hook_id and notification_id, derived
from incident ID/revision/hook identity. Successful queue admission suppresses repeat
dispatch in this session and checkpoint; drops remain eligible. Delivery is best
effort, not exactly once: a crash between side effect and checkpoint can replay a
notification; queued work may be lost. updated/all filters suppress count-only updates
and permit severity escalation or outcome transitions. Closed events are output but
do not run hooks. Children inherit the user's environment and current directory;
no elevation or environment values derived from logs. Operators control hook trust.

Treat payload values as untrusted input even though the event is redacted. Raw log
lines, request targets, User-Agent, Referer and Host are not included; evidence
contains file paths and line numbers only. Parse stdin as JSON and validate the
fields needed by the receiver. Never interpolate payload values into shell source,
eval or command templates. When invoking another program, use a fixed executable
and an argument array (and its end-of-options marker where supported). For example,
a Python receiver can forward the parsed event as JSON without a shell:

```python
import json
import subprocess
import sys

event = json.load(sys.stdin)
subprocess.run(
    ["/opt/webaudit/bin/incident-receiver", "--stdin-json"],
    input=json.dumps(event), text=True, check=True, timeout=5,
)
```

The executable and its options above are operator configuration. Payload JSON is
limited to 64 KiB before the trailing newline; oversized notifications are dropped
with a warning, rather than truncated into invalid JSON. Downstream receivers need
their own input limits, timeout and safe handling when sending values to other systems.

Cancellation kills the process tree (Unix process group, Windows Job Object) and
reaps the command. Timeout/output limits apply per invocation. Hook result details
must not echo payload secrets. JSON schema is documented alongside watch usage.
