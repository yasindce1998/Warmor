# Streaming delivery and shutdown

Streaming is **best effort and memory-only**, not a durable audit log. Serial
transformation/enrichment is separate from delivery: every registered sink has a
bounded FIFO queue and one worker. A slow webhook or TCP syslog collector cannot
block enrichment or another sink.

## Bounds and ordering

`streaming.PipelineConfig` exposes the following budgets (nonpositive values use
defaults):

| Setting | Default | Meaning |
| --- | --- | --- |
| `BufferSize` | 4096 | Ingress queue; drop newest when full |
| `SinkBufferSize` | 4096 | Independent queue per sink; drop newest when full |
| `WriteTimeout` | 5s | Each write or periodic/final flush |
| `FlushInterval` | 5s | Independent periodic flush per sink |
| `ShutdownTimeout` | 5s | One total drain budget shared by every worker |

Enrichment runs serially in ingress channel order. Each sink sees surviving
events in that order; there is no ordering across sinks. Writes and flushes never
overlap within a pipeline-owned sink. Events passed to sinks are immutable. Do
not register the same sink instance twice or call it externally while the
pipeline owns its lifecycle.

Syslog uses `SyslogConfig.Timeout` (default 5s) covering connection and write
time, further limited by the caller's context. Cancellation interrupts an active
write. A failed/partial record is counted as lost and is not retried; the next
event may reconnect. TCP write/UDP send success does not acknowledge collector
ingestion.

Webhook POSTs are serialized, including concurrent explicit flushes. Each POST
contains at most `BatchSize` events. Transient failures (transport, 429, 5xx)
retain the failed head ahead of newer events, with these limits:

- `MaxPending` defaults to `10 * BatchSize`; overflow drops oldest pending
  events. At most one additional `BatchSize` batch can be in flight.
- `MaxAttempts` defaults to 3 per event, including the first POST.
- `MaxAge` defaults to 5m, checked on writes, flushes and close. The pipeline
  periodically flushes even when no new events arrive.
- After failure, normal writes wait for `FlushEvery` before retrying.
  Explicit/periodic flushes can retry earlier. There is no tight retry loop.
- One flush deadline covers waiting for the preceding flush and all POSTs in
  that flush, not a fresh timeout per batch. Response consumption is capped at
  64 KiB and is subject to the request deadline.

Ambiguous transport failures can cause duplicate delivery on retry. There is no
exactly-once or at-least-once guarantee. Permanent rejection drops the batch.

## Shutdown contract

`Pipeline.Close` stops ingress, drains independent queues, attempts final flushes,
and closes sinks. Concurrent callers wait for the same completed shutdown and
receive the same result. At the shared deadline active network requests/writes
are canceled and queued events are discarded with counters. Retried batches do
not get a fresh background deadline. `WebhookSink.CloseContext` makes a bounded
final attempt and counts/discards remaining retained events. Workers are joined;
there is no abandoned per-call goroutine on timeout.

These bounds require cooperative implementations: `Enricher.Enrich` must return
promptly, sink writes/flushes must honor cancellation, and custom `Close` must
return promptly. A CEF callback, blocked stdout pipe or uninterruptible local
filesystem operation cannot be safely forcibly stopped in Go. Such a sink cannot
stall other sinks during normal delivery, but can delay its own worker and
shutdown. This is not a hard real-time promise for arbitrary callbacks or
filesystems.

## Observability

`Pipeline.Stats()` reports:

- `EventsReceived`: ingress attempts before close.
- `EventsEmitted`: enriched events offered to sink queues, **not deliveries**.
- `EventsDropped`: full/shutdown ingress loss; `ShutdownDropped` is the shutdown
  subset.
- `EventsRejected`: attempts after ingress closes, outside `EventsReceived`.
- `Sinks`: per-registration admission, write, error and loss counters.
  `QueueDropped`, `ShutdownDropped` and `DeliveryDropped` are disjoint loss
  categories. `Written` counts successful `Write` calls, not remote delivery.
  A failed batching write can retain events. A custom sink exposing `Dropped()`
  owns its own retained-delivery loss accounting; otherwise failed writes count
  as delivery loss.

After completed shutdown, `EventsReceived = EventsEmitted + EventsDropped`.
Sink loss counts each fan-out copy, not unique source events.

Prometheus exports `warmor_streaming_dropped_total{boundary,sink}` for ingress
full/closed/shutdown, sink queue full/shutdown, unbuffered write errors, syslog
write loss and webhook cancellation/overflow/expiry/attempt/rejection/shutdown
loss. `warmor_streaming_errors_total{sink,operation}` counts failed pipeline sink
operations independently of loss. Labels use fixed sink classes (`stdout`,
`file`, `syslog`, `webhook`, `cef`, `custom`, `none`), never collector URLs,
credentials, paths or custom names. Per-registration detail, including duplicate
names, remains available in `Stats()`.

Sensor ring/decode/read loss, queues outside this pipeline, durable spooling,
and graph/fingerprint lifecycle bounds remain separate work. These counters do
not imply end-to-end loss coverage or measured deployed CPU/RSS/loss budgets.
