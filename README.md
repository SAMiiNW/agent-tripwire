# AGENT TRIPWIRE

```text
POLICY LOCKED     exact bytes + rule count
ACTION PREFLIGHT  exact violated indexes
SAFE PATH         CLEARED
FAULT PATH        TRIPPED -> RESET / EXPIRED_TRIPPED
```

An agent should not discover its boundary after the irreversible call. This contract freezes a public operating policy before an autonomous action is proposed. The operator and recovery monitor are separate from the owner. Validators retrieve the unchanged policy and the proposed action, then agree on every violated rule index, the severity, the explanation, and both source digests.

`allowed` is not free-form. It is valid only when the violation set is empty and severity is `SAFE`. A mutable policy fails its stored digest. A tripped action can reset only when the named monitor supplies fresh-origin evidence covering the exact violation set. Anyone can expire an abandoned decision or recovery window.

Every fetched policy, action, and recovery document must be valid UTF-8 and no larger than 14,000 bytes. Oversized content is rejected explicitly; it is never truncated for consensus. Recovery validators refetch the complete frozen policy and original action, verify both stored digests, and evaluate each violation against its underlying policy text rather than trusting numeric indexes alone.

## Control states

`ARMED -> CLEARED`

`ARMED -> TRIPPED -> RESET`

`ARMED -> EXPIRED_UNINSPECTED`

`TRIPPED -> EXPIRED_TRIPPED`

## Inspection

```bash
genvm-lint contracts/contract.py
python -m pytest -q
```

The files under `evidence/` are operator-created technical fixtures. They demonstrate the source slots and must not be described as independent authorities.

