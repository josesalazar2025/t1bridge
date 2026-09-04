//! Development-only standard fingerprint smoke command core.
//!
//! This module deliberately owns no socket, queue, hardware path, or account
//! lookup. A future development binary supplies the committed-state and worker
//! callbacks while this core proves admission through the production broker
//! scheduler and renders only redacted standard results.

use core::fmt;
use std::time::Duration;

use crate::auth_protocol::{AccessPolicy, PeerAddressFamily, PeerMetadata};
use crate::auth_scheduler::{
    BrokerServiceScheduler, ScheduledStandardDispatch, ScheduledStandardOperation,
};
use crate::standard_fingerprint_protocol::{
    EnrollProgress, FingerLabel, Identity, ServerMessage, TerminalOutcome, Username,
};
use crate::standard_identity_catalog::StandardIdentityCatalog;
use crate::standard_operation_authority::{ResolvedStandardAccount, ResolvedStandardOperation};

const ROOT_LOCAL_PEER: PeerMetadata = PeerMetadata {
    address_family: PeerAddressFamily::Local,
    user_id: 0,
    group_id: 0,
};

/// One parsed human-facing smoke command. No variant accepts an identity ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StandardSmokeCommand {
    List,
    Enroll {
        username: Username,
        finger: FingerLabel,
    },
    Verify {
        username: Username,
        finger: FingerLabel,
    },
    Identify {
        username: Username,
    },
    Delete {
        username: Username,
        finger: FingerLabel,
    },
}

/// Parses one exact development smoke command.
///
/// Accepted forms are `list`, `enroll USER FINGER`, `verify USER FINGER`,
/// `identify USER`, and `delete USER FINGER`. Finger names are the ten fixed
/// standard labels in lower-case kebab form.
///
/// # Errors
///
/// Rejects every unknown command, wrong arity, invalid username, or nonstandard
/// finger value. Opaque identity strings have no accepted position.
pub fn parse_standard_smoke_command(
    arguments: &[&str],
) -> Result<StandardSmokeCommand, StandardSmokeError> {
    match arguments {
        ["list"] => Ok(StandardSmokeCommand::List),
        ["enroll", username, finger] => Ok(StandardSmokeCommand::Enroll {
            username: parse_username(username)?,
            finger: parse_finger(finger)?,
        }),
        ["verify", username, finger] => Ok(StandardSmokeCommand::Verify {
            username: parse_username(username)?,
            finger: parse_finger(finger)?,
        }),
        ["identify", username] => Ok(StandardSmokeCommand::Identify {
            username: parse_username(username)?,
        }),
        ["delete", username, finger] => Ok(StandardSmokeCommand::Delete {
            username: parse_username(username)?,
            finger: parse_finger(finger)?,
        }),
        _ => Err(StandardSmokeError::Usage),
    }
}

fn parse_username(value: &str) -> Result<Username, StandardSmokeError> {
    Username::new(value).map_err(|_| StandardSmokeError::InvalidUsername)
}

fn parse_finger(value: &str) -> Result<FingerLabel, StandardSmokeError> {
    match value {
        "left-thumb" => Ok(FingerLabel::LeftThumb),
        "left-index" => Ok(FingerLabel::LeftIndex),
        "left-middle" => Ok(FingerLabel::LeftMiddle),
        "left-ring" => Ok(FingerLabel::LeftRing),
        "left-little" => Ok(FingerLabel::LeftLittle),
        "right-thumb" => Ok(FingerLabel::RightThumb),
        "right-index" => Ok(FingerLabel::RightIndex),
        "right-middle" => Ok(FingerLabel::RightMiddle),
        "right-ring" => Ok(FingerLabel::RightRing),
        "right-little" => Ok(FingerLabel::RightLittle),
        _ => Err(StandardSmokeError::InvalidFinger),
    }
}

/// Development seams supplied by the future binary and live worker.
pub trait StandardSmokeEnvironment {
    /// Resolves the asserted name through the production canonical account
    /// boundary. The result must contain the exact asserted canonical name.
    ///
    /// # Errors
    ///
    /// Returns a payload-free failure when canonical account resolution fails.
    fn resolve_account(
        &mut self,
        username: &Username,
    ) -> Result<ResolvedStandardAccount, StandardSmokeEnvironmentError>;

    /// Loads the committed labeled catalog for one freshly resolved account.
    ///
    /// # Errors
    ///
    /// Returns a payload-free failure when committed state cannot be loaded or
    /// does not match the resolved account.
    fn load_catalog(
        &mut self,
        account: &ResolvedStandardAccount,
    ) -> Result<StandardIdentityCatalog, StandardSmokeEnvironmentError>;

    /// Executes only work already admitted to the production scheduler.
    fn run_worker(
        &mut self,
        scheduled: &ScheduledStandardOperation,
        progress: &mut dyn FnMut(EnrollProgress),
    ) -> StandardSmokeWorkerResult;
}

/// One injected worker result. Cancellation is still routed by the scheduler.
pub struct StandardSmokeWorkerResult {
    pub response: ServerMessage,
    pub cancel_before_finish: bool,
}

/// Payload-free failure at an injected production environment boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StandardSmokeEnvironmentError;

/// Concise redacted report suitable for development CLI output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StandardSmokeReport {
    Finger(FingerLabel),
    Count(usize),
    Status(StandardSmokeStatus),
}

impl fmt::Display for StandardSmokeReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Finger(finger) => write!(formatter, "success finger {}", finger_name(*finger)),
            Self::Count(count) => write!(formatter, "success count {count}"),
            Self::Status(status) => write!(formatter, "status {}", status.as_str()),
        }
    }
}

/// Fixed payload-free status vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StandardSmokeStatus {
    NoMatch,
    Cancelled,
    DeviceLost,
    Busy,
    SecondOwner,
    Unsupported,
    Duplicate,
    CapacityFull,
    Error,
}

impl StandardSmokeStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NoMatch => "no-match",
            Self::Cancelled => "cancelled",
            Self::DeviceLost => "device-lost",
            Self::Busy => "busy",
            Self::SecondOwner => "second-owner",
            Self::Unsupported => "unsupported",
            Self::Duplicate => "duplicate",
            Self::CapacityFull => "capacity-full",
            Self::Error => "error",
        }
    }
}

/// Resolves one human command, admits it through the production scheduler,
/// invokes one injected worker, binds its completion to the scheduled token,
/// and finalizes through `finish_standard`.
///
/// No caller can replace the root-local peer, scheduler, or active token. The
/// worker receives the exact `ScheduledStandardOperation`; requested
/// cancellation is delivered back through that scheduler before completion.
///
/// # Errors
///
/// Refuses account or committed-state failures, ambiguous finger labels,
/// scheduler termination, nonterminal worker results, and incompatible output.
pub fn execute_standard_smoke(
    scheduler: &mut BrokerServiceScheduler,
    command: StandardSmokeCommand,
    recorded_owner: Option<AccessPolicy>,
    now: Duration,
    environment: &mut impl StandardSmokeEnvironment,
    progress: &mut dyn FnMut(EnrollProgress),
) -> Result<StandardSmokeReport, StandardSmokeError> {
    let prepared = prepare_operation(command, environment)?;
    let dispatch =
        scheduler.dispatch_standard(ROOT_LOCAL_PEER, recorded_owner, prepared.operation, now);
    let ScheduledStandardDispatch::Start(admitted) = dispatch else {
        return match dispatch {
            ScheduledStandardDispatch::Reply(response) => {
                render_response(response, prepared.finger, prepared.catalog.as_ref())
            }
            ScheduledStandardDispatch::Terminate => Err(StandardSmokeError::SchedulerTerminated),
            ScheduledStandardDispatch::Start(_) => unreachable!(),
        };
    };

    let worker = environment.run_worker(&admitted, progress);
    if !worker.response.is_terminal() {
        let _ = scheduler.abandon_standard(&admitted, now);
        return Err(StandardSmokeError::NonTerminalWorkerResult);
    }
    if worker.cancel_before_finish && !scheduler.cancel_standard(&admitted) {
        let _ = scheduler.abandon_standard(&admitted, now);
        return Err(StandardSmokeError::CancellationDeliveryFailed);
    }
    let completion = admitted.operation().completion_for_worker(worker.response);
    let response = scheduler.finish_standard(&admitted, &completion, now);
    render_response(response, prepared.finger, prepared.catalog.as_ref())
}

struct PreparedOperation {
    operation: ResolvedStandardOperation,
    finger: Option<FingerLabel>,
    catalog: Option<StandardIdentityCatalog>,
}

fn prepare_operation(
    command: StandardSmokeCommand,
    environment: &mut impl StandardSmokeEnvironment,
) -> Result<PreparedOperation, StandardSmokeError> {
    match command {
        StandardSmokeCommand::List => Ok(PreparedOperation {
            operation: ResolvedStandardOperation::ListIdentities,
            finger: None,
            catalog: None,
        }),
        StandardSmokeCommand::Enroll { username, finger } => {
            let account = resolve_account(environment, &username)?;
            Ok(PreparedOperation {
                operation: ResolvedStandardOperation::Enroll { account, finger },
                finger: Some(finger),
                catalog: None,
            })
        }
        StandardSmokeCommand::Verify { username, finger } => {
            prepare_exact_finger(environment, &username, finger, false)
        }
        StandardSmokeCommand::Identify { username } => {
            let account = resolve_account(environment, &username)?;
            let catalog = environment
                .load_catalog(&account)
                .map_err(|_| StandardSmokeError::CatalogUnavailable)?;
            Ok(PreparedOperation {
                operation: ResolvedStandardOperation::Identify { account },
                finger: None,
                catalog: Some(catalog),
            })
        }
        StandardSmokeCommand::Delete { username, finger } => {
            prepare_exact_finger(environment, &username, finger, true)
        }
    }
}

fn prepare_exact_finger(
    environment: &mut impl StandardSmokeEnvironment,
    username: &Username,
    finger: FingerLabel,
    delete: bool,
) -> Result<PreparedOperation, StandardSmokeError> {
    let account = resolve_account(environment, username)?;
    let catalog = environment
        .load_catalog(&account)
        .map_err(|_| StandardSmokeError::CatalogUnavailable)?;
    let matching: Vec<Identity> = catalog
        .labeled_identities()
        .into_iter()
        .filter(|identity| identity.finger == finger)
        .collect();
    let [identity] = matching.as_slice() else {
        return Err(if matching.is_empty() {
            StandardSmokeError::FingerNotEnrolled
        } else {
            StandardSmokeError::FingerAmbiguous
        });
    };
    let operation = if delete {
        ResolvedStandardOperation::DeleteIdentity {
            account,
            identity: identity.id,
        }
    } else {
        ResolvedStandardOperation::Verify {
            account,
            identity: identity.id,
        }
    };
    Ok(PreparedOperation {
        operation,
        finger: Some(finger),
        catalog: Some(catalog),
    })
}

fn resolve_account(
    environment: &mut impl StandardSmokeEnvironment,
    username: &Username,
) -> Result<ResolvedStandardAccount, StandardSmokeError> {
    let account = environment
        .resolve_account(username)
        .map_err(|_| StandardSmokeError::AccountUnavailable)?;
    if account.canonical_username() != username {
        return Err(StandardSmokeError::AccountUnavailable);
    }
    Ok(account)
}

fn render_response(
    response: ServerMessage,
    requested_finger: Option<FingerLabel>,
    catalog: Option<&StandardIdentityCatalog>,
) -> Result<StandardSmokeReport, StandardSmokeError> {
    match response {
        ServerMessage::IdentityList { identities, .. } => {
            Ok(StandardSmokeReport::Count(identities.len()))
        }
        ServerMessage::Terminal(TerminalOutcome::Completed | TerminalOutcome::Enrolled(_)) => {
            requested_finger
                .map(StandardSmokeReport::Finger)
                .ok_or(StandardSmokeError::UnexpectedResponse)
        }
        ServerMessage::Terminal(TerminalOutcome::Matched(identity)) => {
            if let Some(finger) = requested_finger {
                Ok(StandardSmokeReport::Finger(finger))
            } else {
                catalog
                    .and_then(|catalog| {
                        catalog
                            .labeled_identities()
                            .into_iter()
                            .find(|candidate| candidate.id == identity)
                    })
                    .map(|identity| StandardSmokeReport::Finger(identity.finger))
                    .ok_or(StandardSmokeError::UnexpectedResponse)
            }
        }
        ServerMessage::Terminal(outcome) => Ok(StandardSmokeReport::Status(match outcome {
            TerminalOutcome::NoMatch => StandardSmokeStatus::NoMatch,
            TerminalOutcome::Cancelled => StandardSmokeStatus::Cancelled,
            TerminalOutcome::DeviceLost => StandardSmokeStatus::DeviceLost,
            TerminalOutcome::Busy => StandardSmokeStatus::Busy,
            TerminalOutcome::SecondOwner => StandardSmokeStatus::SecondOwner,
            TerminalOutcome::Unsupported => StandardSmokeStatus::Unsupported,
            TerminalOutcome::Duplicate => StandardSmokeStatus::Duplicate,
            TerminalOutcome::CapacityFull => StandardSmokeStatus::CapacityFull,
            TerminalOutcome::Error => StandardSmokeStatus::Error,
            TerminalOutcome::Completed
            | TerminalOutcome::Enrolled(_)
            | TerminalOutcome::Matched(_) => unreachable!(),
        })),
        ServerMessage::Capabilities(_)
        | ServerMessage::Opened
        | ServerMessage::EnrollProgress(_) => Err(StandardSmokeError::UnexpectedResponse),
    }
}

const fn finger_name(finger: FingerLabel) -> &'static str {
    match finger {
        FingerLabel::LeftThumb => "left-thumb",
        FingerLabel::LeftIndex => "left-index",
        FingerLabel::LeftMiddle => "left-middle",
        FingerLabel::LeftRing => "left-ring",
        FingerLabel::LeftLittle => "left-little",
        FingerLabel::RightThumb => "right-thumb",
        FingerLabel::RightIndex => "right-index",
        FingerLabel::RightMiddle => "right-middle",
        FingerLabel::RightRing => "right-ring",
        FingerLabel::RightLittle => "right-little",
    }
}

/// Payload-free smoke command failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StandardSmokeError {
    Usage,
    InvalidUsername,
    InvalidFinger,
    AccountUnavailable,
    CatalogUnavailable,
    FingerNotEnrolled,
    FingerAmbiguous,
    SchedulerTerminated,
    NonTerminalWorkerResult,
    CancellationDeliveryFailed,
    UnexpectedResponse,
}

impl fmt::Display for StandardSmokeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Usage => "invalid standard fingerprint smoke command",
            Self::InvalidUsername => "standard fingerprint username is invalid",
            Self::InvalidFinger => "standard fingerprint finger is invalid",
            Self::AccountUnavailable => "standard fingerprint account is unavailable",
            Self::CatalogUnavailable => "committed fingerprint catalog is unavailable",
            Self::FingerNotEnrolled => "finger has no labeled enrollment",
            Self::FingerAmbiguous => "finger has multiple labeled enrollments",
            Self::SchedulerTerminated => "standard fingerprint scheduler is unavailable",
            Self::NonTerminalWorkerResult => "standard fingerprint worker did not finish",
            Self::CancellationDeliveryFailed => "standard fingerprint cancellation delivery failed",
            Self::UnexpectedResponse => "standard fingerprint response is incompatible",
        })
    }
}

impl std::error::Error for StandardSmokeError {}
