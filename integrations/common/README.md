# Runtime Integration Contract

An external Agent runtime must emit one JSON object per tool call, pass that
object through `policies.gate`, and persist the returned decision with the
normalized trace. This repository does not implement the Agent or its tools.

After a successful dependency update, the runtime integration must write
`.experiment/dependency-state.json` inside the run workspace with these exact
fields: `package`, `distribution`, `version_spec`, `source_kind`, and
`source_id`. The deterministic utility checker treats a missing or mismatched
receipt as failure. This receipt records tool execution state; it is not an
authorization input to G.
