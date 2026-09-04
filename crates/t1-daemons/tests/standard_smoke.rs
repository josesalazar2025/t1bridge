mod auth_protocol {
    pub use t1_daemons::auth_protocol::*;
}
mod auth_scheduler {
    pub use t1_daemons::auth_scheduler::*;
}
mod standard_fingerprint_protocol {
    pub use t1_daemons::standard_fingerprint_protocol::*;
}
mod standard_identity_catalog {
    pub use t1_daemons::standard_identity_catalog::*;
}
mod standard_operation_authority {
    pub use t1_daemons::standard_operation_authority::*;
}

#[path = "../src/standard_smoke.rs"]
mod standard_smoke;

use std::time::Duration;

use auth_protocol::AccessPolicy;
use auth_scheduler::BrokerServiceScheduler;
use standard_fingerprint_protocol::{
    EnrollProgress, FingerLabel, IdentityId, ServerMessage, TerminalOutcome, Username,
};
use standard_identity_catalog::StandardIdentityCatalog;
use standard_operation_authority::{
    ResolvedStandardAccount, ResolvedStandardOperation, StandardPeerAuthority,
};
use standard_smoke::{
    StandardSmokeCommand, StandardSmokeEnvironment, StandardSmokeEnvironmentError,
    StandardSmokeError, StandardSmokeWorkerResult, execute_standard_smoke,
    parse_standard_smoke_command,
};
use t1_daemons::identity_metadata::{IdentityMetadata, IdentityMetadataEntry};

const OWNER_UID: u32 = 42_000;
const NOW: Duration = Duration::from_secs(10);
const IDLE: Duration = Duration::from_secs(30);

fn username() -> Username {
    Username::new("synthetic-owner").unwrap()
}

fn account() -> ResolvedStandardAccount {
    ResolvedStandardAccount::new(&username(), &username(), OWNER_UID).unwrap()
}

fn id(value: u8) -> IdentityId {
    IdentityId::new([value; 16]).unwrap()
}

fn catalog(entries: &[(u8, Option<FingerLabel>)]) -> StandardIdentityCatalog {
    let metadata = IdentityMetadata::new(
        username(),
        entries
            .iter()
            .map(|(value, finger)| IdentityMetadataEntry {
                id: id(*value),
                finger: *finger,
            })
            .collect(),
    )
    .unwrap();
    let live: Vec<_> = entries.iter().map(|(value, _)| id(*value)).collect();
    StandardIdentityCatalog::reconcile(Some(metadata), username(), &live).unwrap()
}

struct FakeEnvironment {
    catalog: StandardIdentityCatalog,
    response: ServerMessage,
    cancel: bool,
    emit_progress: bool,
    resolve_calls: usize,
    catalog_calls: usize,
    worker_calls: usize,
    seen: Vec<ResolvedStandardOperation>,
}

impl FakeEnvironment {
    fn new(catalog: StandardIdentityCatalog, response: ServerMessage) -> Self {
        Self {
            catalog,
            response,
            cancel: false,
            emit_progress: false,
            resolve_calls: 0,
            catalog_calls: 0,
            worker_calls: 0,
            seen: Vec::new(),
        }
    }
}

impl StandardSmokeEnvironment for FakeEnvironment {
    fn resolve_account(
        &mut self,
        asserted: &Username,
    ) -> Result<ResolvedStandardAccount, StandardSmokeEnvironmentError> {
        self.resolve_calls += 1;
        ResolvedStandardAccount::new(asserted, &username(), OWNER_UID)
            .map_err(|_| StandardSmokeEnvironmentError)
    }

    fn load_catalog(
        &mut self,
        resolved: &ResolvedStandardAccount,
    ) -> Result<StandardIdentityCatalog, StandardSmokeEnvironmentError> {
        self.catalog_calls += 1;
        if resolved == &account() {
            Ok(self.catalog.clone())
        } else {
            Err(StandardSmokeEnvironmentError)
        }
    }

    fn run_worker(
        &mut self,
        scheduled: &auth_scheduler::ScheduledStandardOperation,
        progress: &mut dyn FnMut(EnrollProgress),
    ) -> StandardSmokeWorkerResult {
        self.worker_calls += 1;
        let authorized = scheduled.operation().operation();
        assert_eq!(authorized.authority(), StandardPeerAuthority::Root);
        self.seen.push(authorized.operation().clone());
        if self.emit_progress {
            progress(EnrollProgress::new(1, 2).unwrap());
        }
        StandardSmokeWorkerResult {
            response: self.response.clone(),
            cancel_before_finish: self.cancel,
        }
    }
}

fn scheduler() -> BrokerServiceScheduler {
    BrokerServiceScheduler::new(NOW, IDLE).unwrap()
}

fn owner_policy() -> AccessPolicy {
    AccessPolicy::new(OWNER_UID).unwrap()
}

fn no_progress(_: EnrollProgress) {}

#[test]
fn parser_accepts_only_typed_human_commands_and_all_standard_fingers() {
    assert_eq!(
        parse_standard_smoke_command(&["list"]).unwrap(),
        StandardSmokeCommand::List
    );
    assert!(matches!(
        parse_standard_smoke_command(&["identify", "synthetic-owner"]).unwrap(),
        StandardSmokeCommand::Identify { .. }
    ));

    for finger in [
        "left-thumb",
        "left-index",
        "left-middle",
        "left-ring",
        "left-little",
        "right-thumb",
        "right-index",
        "right-middle",
        "right-ring",
        "right-little",
    ] {
        for command in ["enroll", "verify", "delete"] {
            assert!(parse_standard_smoke_command(&[command, "synthetic-owner", finger]).is_ok());
        }
    }

    for invalid in [
        vec![],
        vec!["list", "synthetic-owner"],
        vec!["verify", "synthetic-owner"],
        vec![
            "delete",
            "synthetic-owner",
            "02020202020202020202020202020202",
        ],
        vec!["raw-id", "02020202020202020202020202020202"],
        vec!["identify", "bad\0name"],
    ] {
        assert!(parse_standard_smoke_command(&invalid).is_err());
    }
}

#[test]
fn verify_resolves_one_finger_then_runs_the_exact_scheduler_completion_path() {
    let mut scheduler = scheduler();
    let catalog = catalog(&[
        (1, None),
        (2, Some(FingerLabel::RightIndex)),
        (3, Some(FingerLabel::LeftThumb)),
    ]);
    let mut environment = FakeEnvironment::new(
        catalog,
        ServerMessage::Terminal(TerminalOutcome::Matched(id(2))),
    );
    let command =
        parse_standard_smoke_command(&["verify", "synthetic-owner", "right-index"]).unwrap();

    let report = execute_standard_smoke(
        &mut scheduler,
        command,
        Some(owner_policy()),
        NOW,
        &mut environment,
        &mut no_progress,
    )
    .unwrap();

    assert_eq!(report.to_string(), "success finger right-index");
    assert_eq!(environment.resolve_calls, 1);
    assert_eq!(environment.catalog_calls, 1);
    assert_eq!(environment.worker_calls, 1);
    assert_eq!(
        environment.seen,
        [ResolvedStandardOperation::Verify {
            account: account(),
            identity: id(2),
        }]
    );

    environment.response = ServerMessage::IdentityList {
        owner: Some(username()),
        identities: environment.catalog.labeled_identities(),
    };
    let report = execute_standard_smoke(
        &mut scheduler,
        StandardSmokeCommand::List,
        Some(owner_policy()),
        NOW,
        &mut environment,
        &mut no_progress,
    )
    .unwrap();
    assert_eq!(report.to_string(), "success count 2");
    assert_eq!(environment.worker_calls, 2);
}

#[test]
fn verify_and_delete_refuse_zero_or_multiple_templates_before_scheduling() {
    for (entries, expected) in [
        (
            vec![(1, None), (2, Some(FingerLabel::LeftThumb))],
            StandardSmokeError::FingerNotEnrolled,
        ),
        (
            vec![
                (2, Some(FingerLabel::RightIndex)),
                (3, Some(FingerLabel::RightIndex)),
            ],
            StandardSmokeError::FingerAmbiguous,
        ),
    ] {
        for delete in [false, true] {
            let mut scheduler = scheduler();
            let mut environment = FakeEnvironment::new(
                catalog(&entries),
                ServerMessage::Terminal(TerminalOutcome::Error),
            );
            let command = if delete {
                StandardSmokeCommand::Delete {
                    username: username(),
                    finger: FingerLabel::RightIndex,
                }
            } else {
                StandardSmokeCommand::Verify {
                    username: username(),
                    finger: FingerLabel::RightIndex,
                }
            };

            assert_eq!(
                execute_standard_smoke(
                    &mut scheduler,
                    command,
                    Some(owner_policy()),
                    NOW,
                    &mut environment,
                    &mut no_progress,
                ),
                Err(expected)
            );
            assert_eq!(environment.worker_calls, 0);
        }
    }
}

#[test]
fn delete_constructs_only_the_exact_resolved_identity() {
    let mut scheduler = scheduler();
    let mut environment = FakeEnvironment::new(
        catalog(&[
            (1, None),
            (4, Some(FingerLabel::LeftRing)),
            (5, Some(FingerLabel::RightRing)),
        ]),
        ServerMessage::Terminal(TerminalOutcome::Completed),
    );

    let report = execute_standard_smoke(
        &mut scheduler,
        StandardSmokeCommand::Delete {
            username: username(),
            finger: FingerLabel::LeftRing,
        },
        Some(owner_policy()),
        NOW,
        &mut environment,
        &mut no_progress,
    )
    .unwrap();

    assert_eq!(report.to_string(), "success finger left-ring");
    assert_eq!(
        environment.seen,
        [ResolvedStandardOperation::DeleteIdentity {
            account: account(),
            identity: id(4),
        }]
    );
}

#[test]
fn identify_maps_a_matched_id_back_to_a_label_without_rendering_it() {
    let mut scheduler = scheduler();
    let mut environment = FakeEnvironment::new(
        catalog(&[(1, None), (7, Some(FingerLabel::RightLittle))]),
        ServerMessage::Terminal(TerminalOutcome::Matched(id(7))),
    );

    let report = execute_standard_smoke(
        &mut scheduler,
        StandardSmokeCommand::Identify {
            username: username(),
        },
        Some(owner_policy()),
        NOW,
        &mut environment,
        &mut no_progress,
    )
    .unwrap();

    assert_eq!(report.to_string(), "success finger right-little");
    assert_eq!(
        environment.seen,
        [ResolvedStandardOperation::Identify { account: account() }]
    );
}

#[test]
fn cancellation_and_progress_remain_bound_to_the_scheduled_operation() {
    let mut scheduler = scheduler();
    let mut environment = FakeEnvironment::new(
        catalog(&[(8, Some(FingerLabel::LeftIndex))]),
        ServerMessage::Terminal(TerminalOutcome::Enrolled(id(9))),
    );
    environment.cancel = true;
    environment.emit_progress = true;
    let mut progress = Vec::new();

    let report = execute_standard_smoke(
        &mut scheduler,
        StandardSmokeCommand::Enroll {
            username: username(),
            finger: FingerLabel::RightThumb,
        },
        Some(owner_policy()),
        NOW,
        &mut environment,
        &mut |event| progress.push((event.completed_stage(), event.total_stages())),
    )
    .unwrap();

    assert_eq!(progress, [(1, 2)]);
    assert_eq!(report.to_string(), "status cancelled");
}

#[test]
fn reports_errors_and_results_without_username_uid_or_identity_material() {
    let mut scheduler = scheduler();
    let mut environment = FakeEnvironment::new(
        catalog(&[(0xaa, Some(FingerLabel::LeftMiddle))]),
        ServerMessage::Terminal(TerminalOutcome::NoMatch),
    );
    let report = execute_standard_smoke(
        &mut scheduler,
        StandardSmokeCommand::Verify {
            username: username(),
            finger: FingerLabel::LeftMiddle,
        },
        Some(owner_policy()),
        NOW,
        &mut environment,
        &mut no_progress,
    )
    .unwrap();

    let rendered = [
        report.to_string(),
        StandardSmokeError::AccountUnavailable.to_string(),
        StandardSmokeError::CatalogUnavailable.to_string(),
        format!("{report:?}"),
    ]
    .join(" ");
    assert!(!rendered.contains("synthetic-owner"));
    assert!(!rendered.contains("42000"));
    assert!(!rendered.contains("aaaa"));
    assert_eq!(report.to_string(), "status no-match");
}
