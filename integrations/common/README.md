# Runtime Integration Contract

An external Agent runtime must emit one JSON object per tool call, pass that
object through `policies.gate`, and persist the returned decision with the
normalized trace. This repository does not implement the Agent or its tools.
