# Disk capacity pressure response

Applies to rules: `disk_pressure`.

## What this pattern means

A host reporting disk usage over the warning threshold is on a path to a full
filesystem. A full volume stops log writing first — which blinds every other
detection on that host — and then stops the services that write to it.

## Immediate steps

1. Identify the growing path (logs, spool, database files) on the named host.
2. Free or expand storage before the critical threshold; prefer archiving over
   deletion so evidence is not destroyed.
3. If growth is sudden rather than gradual, treat it as a symptom: check for a
   crash-looping service, a runaway job, or bulk data staging by an intruder.

## Evidence to preserve

The disk percentage readings and their timestamps from the finding, and a
snapshot of the largest directories on the affected volume.
