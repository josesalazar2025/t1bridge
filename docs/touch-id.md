# How Touch ID works

Linux applications use **fprintd**. Its libfprint driver asks **T1Bridge** to
perform the operation; T1Bridge coordinates the **T1 Secure Enclave**, where
finger capture and matching happen. The Touch Bar displays progress and results
but cannot authorize anything.

These diagrams describe the standard fprintd path, not the direct development
CLI. They describe implementation behavior, not completed release acceptance;
see the [release gate](release-gate/v1.md) for current evidence.

## Startup: make the hardware ready

```mermaid
flowchart TD
    USB["T1 enumerates"] --> CFG["Kernel selects the validated USB configuration"]
    CFG --> LINK["Private NCM link becomes ready"]
    CFG --> BAR["Touch Bar hardware and user renderer"]
    LINK --> XART["xART storage listener ready"]
    XART --> SAVED{"Saved keybag exists?"}
    SAVED -->|Yes| RELAY["Start keybag notification relay"]
    SAVED -->|No| FIRST["First enrollment bootstraps the keybag"]
    FIRST --> RELAY
    SOCKET["systemd fingerprint socket"] -->|Request| BROKER["Start authentication broker"]
    RELAY -. "required for operation handoff" .-> BROKER
    DATA["Validated local Apple machine data"] -. "required for biometric operations" .-> BROKER

    classDef hardware fill:#dbeafe,stroke:#2563eb,color:#172554
    classDef service fill:#dcfce7,stroke:#15803d,color:#14532d
    classDef state fill:#fef3c7,stroke:#b45309,color:#451a03
    class USB,CFG,LINK hardware
    class XART,RELAY,BROKER,BAR,SOCKET service
    class DATA,SAVED,FIRST state
```

NCM is the private network link to the T1. xART stores opaque anti-replay data.
The keybag relay maintains the device's notification session between biometric
operations; it is not the fingerprint matcher. A socket can be listening even
when the hardware is not ready.

Apple machine data is imported locally from a matching preserved EFI source.
It is never shipped in a package. Protected state remains root-owned on the
machine; other users and the renderer do not receive it.

Sources: [service ordering](architecture.md#boot-and-ordering-contract),
[xART unit](../systemd/t1-xart-storage@.service),
[keybag unit](../systemd/t1bridge-keybag.service).

## Enrollment: capture, then commit

```mermaid
flowchart TD
    CLIENT["Fingerprint manager: choose hand and finger"] --> AUTH["fprintd checks authorization"]
    AUTH --> DRIVER["libfprint sends the target account and finger label"]
    DRIVER --> OWNER["Broker validates the account and single enrollment owner"]
    OWNER --> READY["Ensure keybag and relay are ready"]
    READY --> LEASE["Stop relay; acquire exclusive SEP operation"]
    LEASE --> PREP["Prepare user state, protected storage and policy"]
    PREP --> FULL{"Enrollment capacity available?"}
    FULL -->|No| FAIL["Stop without starting enrollment"]
    FULL -->|Yes| CHECK["Check for an existing print when identities exist"]
    CHECK -->|Duplicate| FAIL
    CHECK -->|New finger or first enrollment| CAPTURE["Lift and touch repeatedly; report capture progress"]
    CAPTURE --> SAVE["Export user, then master; durably promote paired state and labels"]
    SAVE --> VERIFY["Re-read identities; require exactly the expected new set"]
    VERIFY --> CLEAN["Release SEP; restore relay"]
    CLEAN --> OK["Report enrollment complete"]
    FAIL --> RECOVER["Release owned resources; attempt relay recovery"]
    RECOVER --> REJECT["Report failure, not enrollment success"]

    classDef standard fill:#dbeafe,stroke:#2563eb,color:#172554
    classDef broker fill:#dcfce7,stroke:#15803d,color:#14532d
    classDef device fill:#fef3c7,stroke:#b45309,color:#451a03
    classDef error fill:#fee2e2,stroke:#b91c1c,color:#7f1d1d
    class CLIENT,AUTH,DRIVER standard
    class OWNER,READY,LEASE,PREP,SAVE,VERIFY,CLEAN,RECOVER,OK broker
    class FULL,CHECK,CAPTURE device
    class FAIL,REJECT error
```

Duplicate detection and capture share the enrollment operation; the duplicate
check is not a second authorization prompt. If the keybag needs bootstrapping,
that preparation happens **before** the enrollment relay handoff—not inside the
capture lease. Authorization UI belongs to the caller's fprintd/Polkit policy;
an already privileged caller may need no further prompt.

Capture progress is not success. T1Bridge reports completion only after paired
storage, identity verification, and relay recovery succeed. Errors, timeout,
device loss, or cancellation trigger cleanup instead. A failure after device
mutation can leave protected recovery state; it does not mean nothing changed.
Do not delete state files to retry.

The backend limits new enrollment to three identities for one Linux owner. It
can still list and reduce older sets up to the device protocol's five-identity
bound. A reusable fingerprint manager must not hardcode those T1 limits.

Sources: `run_live_enroll` and `prepare_enrollment_relay` in
[live operations](../crates/t1-daemons/src/live_standard_fingerprint.rs),
[enrollment transaction](../crates/t1-daemons/src/enrollment_transaction/standard_enrollment.rs).

## Authentication: warm match or cold restore

```mermaid
sequenceDiagram
    autonumber
    participant PAM as Application + PAM
    participant FP as fprintd + libfprint driver
    participant TB as T1Bridge broker
    participant SEP as T1 Secure Enclave
    Note over PAM: sudo, lock screen or other PAM consumer
    PAM->>FP: Verify fingerprint
    FP->>TB: Typed verify / identify request
    TB->>TB: Validate owner, catalog and operation admission
    Note over TB: Publish cosmetic Touch Bar prompt
    TB->>TB: Stop relay<br/>Acquire exclusive SEP lease
    TB->>SEP: Calibrate, authorize<br/>and reassert user policy
    alt Valid live user state
        SEP-->>TB: Live identities available
    else State needs restoring after boot
        TB->>SEP: Load and validate master,<br/>then paired user
        TB->>TB: Release lease<br/>Restart relay
        TB->>TB: Fresh handoff and lease<br/>Revalidate live state
        Note over TB,SEP: A second restore is an error, not a retry loop
    end
    TB->>SEP: Start matching<br/>Wait for a finger
    SEP-->>TB: Match / no match / error
    TB->>TB: Release lease and restore relay<br/>Validate requested identity
    Note over TB: Publish cosmetic success or retry feedback
    TB-->>FP: Verified outcome, or failure
    FP-->>PAM: Fingerprint result
    alt Accepted fingerprint
        Note over PAM: Continue according to the PAM stack
    else Rejected / unavailable / timed out / cancelled
        Note over PAM: Existing password path remains available
    end
```

A warm match uses one lease. A cold restore deliberately finishes its lease and
restores the relay before a second lease attempts matching. The broker allows
one active operation; another request receives Busy instead of a queued prompt.

Fingerprint failure must never lock out the password path. This depends on the
consumer's PAM configuration: T1Bridge does not edit it or guarantee that a
third-party stack is configured correctly. Password and fingerprint prompts
need not appear simultaneously.

The renderer gets only cosmetic state and may request cancellation through the
hardware service. Its pixels, animations, and progress values are never
authentication evidence. Kernel peer checks, the selected account, the saved
catalog, and the device result determine the outcome.

Sources: `complete_match_after_restore`, `run_live_match_pass`, and
`run_live_query` in [live operations](../crates/t1-daemons/src/live_standard_fingerprint.rs),
[relay handoff](../crates/t1-daemons/src/auth_lifecycle.rs),
[public interfaces](interfaces.md), [security boundaries](security-review/v1.md).
