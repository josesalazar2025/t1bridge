//! Bounded synchronous event loop for the systemd-activated Touch ID broker.

use core::fmt;
use std::env;
use std::ffi::CStr;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, TryRecvError, sync_channel};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use t1_platform::sep::SepCancellationSource;
use t1_platform::seqpacket::{
    SeqPacketError, SystemdActivationPair, SystemdSeqPacketListener, SystemdSeqPacketListenerPair,
};

use crate::auth_scheduler::{BrokerServiceScheduler, LifecycleDecision, SchedulerError};
use crate::auth_session::{
    ActiveAuthentication, AuthenticationCompletion, AuthenticationSessionFailure,
};
use crate::auth_socket::{
    ActivatedBrokerSocketListener, ActiveBrokerSocketSession, BrokerReplyProgress,
    BrokerSocketConnection, BrokerSocketDispatch, BrokerSocketError, DisconnectObservation,
    PendingBrokerReply,
};
use crate::enrollment_owner::EnrollmentOwnerStore;
use crate::service_lifecycle::{ServiceLifecycle, ServiceLifecycleError};
use crate::standard_connection::{StandardConnectionConfig, StandardWorkerJob};
use crate::standard_fingerprint_protocol::EnrollProgress;
use crate::standard_socket::{
    ActivatedStandardSocketListener, StandardSocketConnection, StandardSocketError,
    StandardSocketEvent,
};

const OWNER_DIRECTORY: &str = "/var/lib/t1bridge/touch-id/catacombs";
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_millis(250);
const REPLY_TIMEOUT: Duration = Duration::from_millis(250);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
const EVENT_TICK: Duration = Duration::from_millis(10);
const MAX_PENDING_CONNECTIONS: usize = 64;
const MAX_ACCEPTS_PER_TICK: usize = 32;
const STANDARD_ENROLL_STAGES: u8 = 100;
const AUTH_SOCKET_PATH: &CStr = c"/run/t1-touchid/auth.sock";
const FINGERPRINT_SOCKET_PATH: &CStr = c"/run/t1bridge/fingerprint.sock";
const AUTH_SOCKET_NAME: &str = "t1-touchid-auth.socket";
const FINGERPRINT_SOCKET_NAME: &str = "t1bridge-fingerprint.socket";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ListenerOrder {
    DirectFirst,
    StandardFirst,
}

/// Redaction-safe daemon lifecycle failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthDaemonError {
    Activation,
    Lifecycle,
    Listener,
    Scheduler,
    WorkerLost,
    Shutdown,
}

impl fmt::Display for AuthDaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Activation => "authentication broker activation failed",
            Self::Lifecycle => "authentication broker lifecycle failed",
            Self::Listener => "authentication broker listener failed",
            Self::Scheduler => "authentication broker authority became uncertain",
            Self::WorkerLost => "authentication broker worker was lost",
            Self::Shutdown => "authentication broker shutdown did not complete",
        })
    }
}

impl std::error::Error for AuthDaemonError {}

/// One injected product worker. The event loop never runs more than one call
/// concurrently and retains all socket, scheduling, and cancellation authority.
pub trait BrokerWorker: Send + Sync + 'static {
    fn run(&self, active: ActiveAuthentication) -> AuthenticationCompletion;
}

impl<Worker> BrokerWorker for Worker
where
    Worker: Fn(ActiveAuthentication) -> AuthenticationCompletion + Send + Sync + 'static,
{
    fn run(&self, active: ActiveAuthentication) -> AuthenticationCompletion {
        self(active)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct UnavailableWorker;

impl BrokerWorker for UnavailableWorker {
    fn run(&self, active: ActiveAuthentication) -> AuthenticationCompletion {
        active.completion_for_worker(Err(AuthenticationSessionFailure::Operation))
    }
}

/// One injected standard-fingerprint worker. Progress and completion remain
/// bound to the scheduler-authorized operation supplied by the event loop.
pub trait StandardBrokerWorker: Send + Sync + 'static {
    fn run(
        &self,
        active: &crate::auth_session::ActiveStandardOperation,
        progress: &mut dyn FnMut(EnrollProgress),
    ) -> crate::auth_session::StandardCompletion;
}

#[derive(Clone, Copy, Debug, Default)]
struct UnavailableStandardWorker;

impl StandardBrokerWorker for UnavailableStandardWorker {
    fn run(
        &self,
        active: &crate::auth_session::ActiveStandardOperation,
        _progress: &mut dyn FnMut(EnrollProgress),
    ) -> crate::auth_session::StandardCompletion {
        active.completion_for_worker(
            crate::standard_fingerprint_protocol::ServerMessage::Terminal(
                crate::standard_fingerprint_protocol::TerminalOutcome::Error,
            ),
        )
    }
}

/// Runs the production broker with its intentionally unavailable placeholder
/// worker. Live biometric composition is injected separately.
///
/// # Errors
///
/// Returns a static failure if activation, lifecycle ownership, listener
/// authority, scheduling, or worker ownership becomes uncertain.
pub fn run_unavailable_worker() -> Result<(), AuthDaemonError> {
    run_with_worker(UnavailableWorker)
}

/// Runs the production systemd-activated broker with one injected worker.
///
/// # Errors
///
/// Returns a static failure if activation, lifecycle ownership, listener
/// authority, scheduling, or worker ownership becomes uncertain.
pub fn run_with_worker<Worker: BrokerWorker>(worker: Worker) -> Result<(), AuthDaemonError> {
    run_with_workers(worker, UnavailableStandardWorker)
}

/// Runs both direct and standard protocols over one scheduler and worker slot.
///
/// # Errors
///
/// Returns a static failure if activation, lifecycle ownership, listener
/// authority, scheduling, or worker ownership becomes uncertain.
pub fn run_with_workers<Worker, StandardWorker>(
    worker: Worker,
    standard_worker: StandardWorker,
) -> Result<(), AuthDaemonError>
where
    Worker: BrokerWorker,
    StandardWorker: StandardBrokerWorker,
{
    let listen_pid = env::var("LISTEN_PID").map_err(|_| AuthDaemonError::Activation)?;
    let listen_fds = env::var("LISTEN_FDS").map_err(|_| AuthDaemonError::Activation)?;
    let listen_fd_names = env::var("LISTEN_FDNAMES").map_err(|_| AuthDaemonError::Activation)?;
    let activation = parse_activation_pair(&listen_pid, &listen_fds)?;
    let listener_order = parse_listener_order(&listen_fd_names)?;
    let lifecycle = ServiceLifecycle::install().map_err(map_lifecycle_error)?;
    let (direct_listener, standard_listener) = adopt_broker_listeners(activation, listener_order)?;
    let listener = ActivatedBrokerSocketListener::from_systemd_listener(direct_listener);
    let standard_listener =
        ActivatedStandardSocketListener::from_systemd_listener(standard_listener);
    let mut service =
        BrokerServiceScheduler::new(Duration::ZERO, IDLE_TIMEOUT).map_err(map_scheduler_error)?;
    let owner_store = EnrollmentOwnerStore::new(OWNER_DIRECTORY);
    let standard_config = StandardConnectionConfig::new(STANDARD_ENROLL_STAGES)
        .map_err(|_| AuthDaemonError::Activation)?;
    lifecycle.notify_ready().map_err(map_lifecycle_error)?;
    let worker: Arc<dyn BrokerWorker> = Arc::new(worker);
    let standard_worker: Arc<dyn StandardBrokerWorker> = Arc::new(standard_worker);

    let result = run_event_loop(
        EventLoopContext {
            listener: &listener,
            standard_listener: &standard_listener,
            standard_config,
            owner_store: &owner_store,
            worker: &worker,
            standard_worker: &standard_worker,
            lifecycle: &lifecycle,
        },
        &mut service,
    );
    let restored = lifecycle.restore().map_err(map_lifecycle_error);
    result.and(restored)
}

fn parse_activation_pair(
    listen_pid: &str,
    listen_fds: &str,
) -> Result<SystemdActivationPair, AuthDaemonError> {
    SystemdActivationPair::parse(listen_pid, listen_fds).map_err(|_| AuthDaemonError::Activation)
}

fn parse_listener_order(listen_fd_names: &str) -> Result<ListenerOrder, AuthDaemonError> {
    let mut names = listen_fd_names.split(':');
    match (names.next(), names.next(), names.next()) {
        (Some(AUTH_SOCKET_NAME), Some(FINGERPRINT_SOCKET_NAME), None) => {
            Ok(ListenerOrder::DirectFirst)
        }
        (Some(FINGERPRINT_SOCKET_NAME), Some(AUTH_SOCKET_NAME), None) => {
            Ok(ListenerOrder::StandardFirst)
        }
        _ => Err(AuthDaemonError::Activation),
    }
}

fn adopt_broker_listeners(
    activation: SystemdActivationPair,
    order: ListenerOrder,
) -> Result<(SystemdSeqPacketListener, SystemdSeqPacketListener), AuthDaemonError> {
    let (first_path, second_path) = match order {
        ListenerOrder::DirectFirst => (AUTH_SOCKET_PATH, FINGERPRINT_SOCKET_PATH),
        ListenerOrder::StandardFirst => (FINGERPRINT_SOCKET_PATH, AUTH_SOCKET_PATH),
    };
    let listeners = SystemdSeqPacketListenerPair::adopt(activation, first_path, second_path)
        .map_err(|_| AuthDaemonError::Activation)?;
    let (first, second) = listeners.into_listeners();
    Ok(match order {
        ListenerOrder::DirectFirst => (first, second),
        ListenerOrder::StandardFirst => (second, first),
    })
}

fn map_lifecycle_error(_: ServiceLifecycleError) -> AuthDaemonError {
    AuthDaemonError::Lifecycle
}

fn map_scheduler_error(_: SchedulerError) -> AuthDaemonError {
    AuthDaemonError::Scheduler
}

struct TimedConnection {
    connection: BrokerSocketConnection<OwnedFd>,
    deadline: Duration,
}

struct TimedReply {
    reply: PendingBrokerReply<OwnedFd>,
    deadline: Duration,
}

struct TimedStandardConnection {
    connection: StandardSocketConnection<OwnedFd>,
    request_deadline: Option<Duration>,
    reply_deadline: Option<Duration>,
}

struct ActiveDirectRun {
    session: ActiveBrokerSocketSession<OwnedFd>,
    worker: WorkerThread,
    disconnect_observed: bool,
}

struct ActiveStandardRun {
    connection: StandardSocketConnection<OwnedFd>,
    job: StandardWorkerJob,
    worker: StandardWorkerThread,
    disconnect_observed: bool,
    reply_deadline: Option<Duration>,
}

enum ActiveRun {
    Direct(ActiveDirectRun),
    Standard(Box<ActiveStandardRun>),
}

struct WorkerThread {
    receiver: Receiver<AuthenticationCompletion>,
    handle: JoinHandle<()>,
}

enum WorkerPoll {
    Pending(WorkerThread),
    Completed(AuthenticationCompletion),
    Lost,
}

enum StandardWorkerEvent {
    Progress(EnrollProgress),
    Completed(crate::auth_session::StandardCompletion),
}

struct StandardWorkerThread {
    receiver: Receiver<StandardWorkerEvent>,
    handle: JoinHandle<()>,
}

enum StandardWorkerPoll {
    Pending(StandardWorkerThread),
    Progress(StandardWorkerThread, EnrollProgress),
    Completed(crate::auth_session::StandardCompletion),
    Lost,
}

impl WorkerThread {
    fn spawn(
        worker: Arc<dyn BrokerWorker>,
        active: &ActiveAuthentication,
    ) -> Result<Self, AuthDaemonError> {
        let active = active.clone_for_worker();
        let (sender, receiver) = sync_channel(1);
        let handle = thread::Builder::new()
            .name("t1-touchid-operation".into())
            .spawn(move || {
                let completion = worker.run(active);
                let _ = sender.send(completion);
            })
            .map_err(|_| AuthDaemonError::WorkerLost)?;
        Ok(Self { receiver, handle })
    }

    fn poll(self) -> WorkerPoll {
        match self.receiver.try_recv() {
            Ok(completion) => {
                if self.handle.join().is_ok() {
                    WorkerPoll::Completed(completion)
                } else {
                    WorkerPoll::Lost
                }
            }
            Err(TryRecvError::Empty) if !self.handle.is_finished() => WorkerPoll::Pending(self),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => {
                let _ = self.handle.join();
                WorkerPoll::Lost
            }
        }
    }
}

impl StandardWorkerThread {
    fn spawn(
        worker: Arc<dyn StandardBrokerWorker>,
        job: &StandardWorkerJob,
    ) -> Result<Self, AuthDaemonError> {
        let active = job.operation().clone_for_worker();
        let (sender, receiver) = sync_channel(1);
        let handle = thread::Builder::new()
            .name("t1-standard-fingerprint-operation".into())
            .spawn(move || {
                let mut progress = |progress| {
                    let _ = sender.send(StandardWorkerEvent::Progress(progress));
                };
                let completion = worker.run(&active, &mut progress);
                let _ = sender.send(StandardWorkerEvent::Completed(completion));
            })
            .map_err(|_| AuthDaemonError::WorkerLost)?;
        Ok(Self { receiver, handle })
    }

    fn poll(self) -> StandardWorkerPoll {
        match self.receiver.try_recv() {
            Ok(StandardWorkerEvent::Progress(progress)) => {
                StandardWorkerPoll::Progress(self, progress)
            }
            Ok(StandardWorkerEvent::Completed(completion)) => {
                if self.handle.join().is_ok() {
                    StandardWorkerPoll::Completed(completion)
                } else {
                    StandardWorkerPoll::Lost
                }
            }
            Err(TryRecvError::Empty) if !self.handle.is_finished() => {
                StandardWorkerPoll::Pending(self)
            }
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => {
                let _ = self.handle.join();
                StandardWorkerPoll::Lost
            }
        }
    }
}

#[derive(Clone, Copy)]
struct EventLoopContext<'a> {
    listener: &'a ActivatedBrokerSocketListener,
    standard_listener: &'a ActivatedStandardSocketListener,
    standard_config: StandardConnectionConfig,
    owner_store: &'a EnrollmentOwnerStore,
    worker: &'a Arc<dyn BrokerWorker>,
    standard_worker: &'a Arc<dyn StandardBrokerWorker>,
    lifecycle: &'a ServiceLifecycle,
}

#[allow(clippy::too_many_lines)]
fn run_event_loop(
    context: EventLoopContext<'_>,
    service: &mut BrokerServiceScheduler,
) -> Result<(), AuthDaemonError> {
    let EventLoopContext {
        listener,
        standard_listener,
        standard_config,
        owner_store,
        worker,
        standard_worker,
        lifecycle,
    } = context;
    let origin = Instant::now();
    let mut connections = Vec::new();
    let mut standard_connections = Vec::new();
    let mut replies = Vec::new();
    let mut active: Option<ActiveRun> = None;
    let mut shutdown_deadline = None;

    loop {
        let now = origin.elapsed();
        if lifecycle.is_cancelled() && shutdown_deadline.is_none() {
            shutdown_deadline = Some(now.saturating_add(SHUTDOWN_GRACE));
            connections.clear();
            standard_connections.clear();
            if let Some(running) = active.as_ref() {
                let delivered = match running {
                    ActiveRun::Direct(running) => running.session.deadline_expired(service),
                    ActiveRun::Standard(running) => running.connection.deadline_expired(service),
                };
                let _ = delivered;
            }
        }

        let accepting = shutdown_deadline.is_none();
        if accepting {
            accept_connections(listener, &mut connections, now)?;
            accept_standard_connections(
                standard_listener,
                standard_config,
                &mut standard_connections,
                now,
            )?;
            process_connections(
                &mut connections,
                &mut replies,
                &mut active,
                service,
                owner_store,
                worker,
                now,
            )?;
            process_standard_connections(
                &mut standard_connections,
                &mut active,
                service,
                owner_store,
                standard_worker,
                now,
            )?;
        }

        observe_active_disconnect(&mut active, service)?;
        process_active_standard_control(&mut active, service, owner_store, now)?;
        let listener_ready = accepting && listener.is_ready().map_err(map_socket_error)?;
        let standard_listener_ready = accepting
            && standard_listener
                .is_ready()
                .map_err(map_standard_socket_error)?;
        match service.decide(
            now,
            listener_ready
                || standard_listener_ready
                || !connections.is_empty()
                || !standard_connections.is_empty(),
        ) {
            LifecycleDecision::Continue => {}
            LifecycleDecision::Cancel(_) => {
                let Some(running) = active.as_ref() else {
                    return Err(AuthDaemonError::Scheduler);
                };
                cancel_or_await_completion(running, service)?;
            }
            LifecycleDecision::ExitIdle => {
                if active.is_none()
                    && connections.is_empty()
                    && standard_connections.is_empty()
                    && replies.is_empty()
                {
                    return Ok(());
                }
            }
            LifecycleDecision::Terminate => return Err(AuthDaemonError::Scheduler),
        }

        flush_standard_replies(&mut standard_connections, now);
        flush_active_standard_reply(&mut active, service, now)?;
        poll_active_worker(
            &mut active,
            &mut standard_connections,
            &mut replies,
            service,
            now,
        )?;
        flush_replies(&mut replies, now);

        if let Some(deadline) = shutdown_deadline {
            if active.is_none() && replies.is_empty() {
                return Ok(());
            }
            if now >= deadline {
                if let Some(running) = active.take() {
                    match running {
                        ActiveRun::Direct(running) => {
                            let _ = running.session.worker_lost(service);
                        }
                        ActiveRun::Standard(mut running) => {
                            let _ = running.connection.worker_lost(service);
                        }
                    }
                }
                return Err(AuthDaemonError::Shutdown);
            }
        }
        thread::sleep(EVENT_TICK);
    }
}

fn accept_connections(
    listener: &ActivatedBrokerSocketListener,
    connections: &mut Vec<TimedConnection>,
    now: Duration,
) -> Result<(), AuthDaemonError> {
    for _ in 0..MAX_ACCEPTS_PER_TICK {
        if connections.len() >= MAX_PENDING_CONNECTIONS
            || !listener.is_ready().map_err(map_socket_error)?
        {
            break;
        }
        match listener.accept() {
            Ok(connection) => connections.push(TimedConnection {
                connection,
                deadline: now.saturating_add(REQUEST_TIMEOUT),
            }),
            Err(BrokerSocketError(SeqPacketError::WouldBlock | SeqPacketError::Interrupted)) => {
                break;
            }
            Err(_) => return Err(AuthDaemonError::Listener),
        }
    }
    Ok(())
}

fn accept_standard_connections(
    listener: &ActivatedStandardSocketListener,
    config: StandardConnectionConfig,
    connections: &mut Vec<TimedStandardConnection>,
    now: Duration,
) -> Result<(), AuthDaemonError> {
    for _ in 0..MAX_ACCEPTS_PER_TICK {
        if connections.len() >= MAX_PENDING_CONNECTIONS
            || !listener.is_ready().map_err(map_standard_socket_error)?
        {
            break;
        }
        match listener.accept(config) {
            Ok(Some(connection)) => connections.push(TimedStandardConnection {
                connection,
                request_deadline: Some(now.saturating_add(REQUEST_TIMEOUT)),
                reply_deadline: None,
            }),
            Ok(None) => {}
            Err(StandardSocketError::Socket(
                SeqPacketError::WouldBlock | SeqPacketError::Interrupted,
            )) => break,
            Err(_) => return Err(AuthDaemonError::Listener),
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn process_connections(
    connections: &mut Vec<TimedConnection>,
    replies: &mut Vec<TimedReply>,
    active: &mut Option<ActiveRun>,
    service: &mut BrokerServiceScheduler,
    owner_store: &EnrollmentOwnerStore,
    worker: &Arc<dyn BrokerWorker>,
    now: Duration,
) -> Result<(), AuthDaemonError> {
    let mut pending = Vec::with_capacity(connections.len());
    while let Some(timed) = connections.pop() {
        if now >= timed.deadline {
            continue;
        }
        match timed
            .connection
            .receive_and_dispatch(service, owner_store, now)
        {
            Ok(BrokerSocketDispatch::Pending(connection)) => pending.push(TimedConnection {
                connection,
                deadline: timed.deadline,
            }),
            Ok(BrokerSocketDispatch::Closed) | Err(_) => {}
            Ok(BrokerSocketDispatch::Reply(reply)) => queue_reply(replies, reply, now),
            Ok(BrokerSocketDispatch::Start(session)) => {
                if active.is_some() {
                    let _ = session.worker_lost(service);
                    return Err(AuthDaemonError::Scheduler);
                }
                match WorkerThread::spawn(Arc::clone(worker), session.authentication()) {
                    Ok(worker) => {
                        *active = Some(ActiveRun::Direct(ActiveDirectRun {
                            session,
                            worker,
                            disconnect_observed: false,
                        }));
                    }
                    Err(_) => queue_reply(replies, session.abandon(service, now), now),
                }
            }
            Ok(BrokerSocketDispatch::Terminate) => return Err(AuthDaemonError::Scheduler),
        }
    }
    *connections = pending;
    Ok(())
}

fn process_standard_connections(
    connections: &mut Vec<TimedStandardConnection>,
    active: &mut Option<ActiveRun>,
    service: &mut BrokerServiceScheduler,
    owner_store: &EnrollmentOwnerStore,
    worker: &Arc<dyn StandardBrokerWorker>,
    now: Duration,
) -> Result<(), AuthDaemonError> {
    let mut pending = Vec::with_capacity(connections.len());
    while let Some(mut timed) = connections.pop() {
        if timed
            .request_deadline
            .is_some_and(|deadline| now >= deadline)
            || timed.reply_deadline.is_some_and(|deadline| now >= deadline)
        {
            continue;
        }
        if timed.connection.has_pending_reply() {
            pending.push(timed);
            continue;
        }
        match timed
            .connection
            .receive_and_dispatch(service, owner_store, now)
        {
            Ok(StandardSocketEvent::Closed) => {}
            Ok(StandardSocketEvent::ReplyQueued) => {
                timed.request_deadline = None;
                timed.reply_deadline = Some(now.saturating_add(REPLY_TIMEOUT));
                pending.push(timed);
            }
            Ok(StandardSocketEvent::Start(job)) => {
                timed.request_deadline = None;
                if active.is_some() {
                    let completion = job.completion(
                        crate::standard_fingerprint_protocol::ServerMessage::Terminal(
                            crate::standard_fingerprint_protocol::TerminalOutcome::Error,
                        ),
                    );
                    let _ = timed
                        .connection
                        .finish_worker(service, &completion, now)
                        .map_err(map_standard_socket_error)?;
                    timed.reply_deadline = Some(now.saturating_add(REPLY_TIMEOUT));
                    pending.push(timed);
                    continue;
                }
                if let Ok(worker) = StandardWorkerThread::spawn(Arc::clone(worker), &job) {
                    *active = Some(ActiveRun::Standard(Box::new(ActiveStandardRun {
                        connection: timed.connection,
                        job,
                        worker,
                        disconnect_observed: false,
                        reply_deadline: None,
                    })));
                } else {
                    let completion = job.completion(
                        crate::standard_fingerprint_protocol::ServerMessage::Terminal(
                            crate::standard_fingerprint_protocol::TerminalOutcome::Error,
                        ),
                    );
                    let _ = timed
                        .connection
                        .finish_worker(service, &completion, now)
                        .map_err(map_standard_socket_error)?;
                    timed.reply_deadline = Some(now.saturating_add(REPLY_TIMEOUT));
                    pending.push(timed);
                }
            }
            Ok(StandardSocketEvent::Pending | StandardSocketEvent::CancellationPending) => {
                pending.push(timed);
            }
            Ok(StandardSocketEvent::Terminate) | Err(_) => {
                return Err(AuthDaemonError::Scheduler);
            }
        }
    }
    *connections = pending;
    Ok(())
}

fn process_active_standard_control(
    active: &mut Option<ActiveRun>,
    service: &mut BrokerServiceScheduler,
    owner_store: &EnrollmentOwnerStore,
    now: Duration,
) -> Result<(), AuthDaemonError> {
    let Some(ActiveRun::Standard(running)) = active.as_mut() else {
        return Ok(());
    };
    if running.disconnect_observed || running.connection.has_pending_reply() {
        return Ok(());
    }
    match running
        .connection
        .receive_and_dispatch(service, owner_store, now)
    {
        Ok(StandardSocketEvent::Pending | StandardSocketEvent::CancellationPending) => Ok(()),
        Ok(StandardSocketEvent::Closed) => disconnect_standard_run(running, service),
        Ok(StandardSocketEvent::ReplyQueued) => {
            running.reply_deadline = Some(now.saturating_add(REPLY_TIMEOUT));
            Ok(())
        }
        Ok(StandardSocketEvent::Start(_) | StandardSocketEvent::Terminate) | Err(_) => {
            Err(AuthDaemonError::Scheduler)
        }
    }
}

fn observe_active_disconnect(
    active: &mut Option<ActiveRun>,
    service: &mut BrokerServiceScheduler,
) -> Result<(), AuthDaemonError> {
    let Some(running) = active.as_mut() else {
        return Ok(());
    };
    match running {
        ActiveRun::Direct(running) => {
            if running.disconnect_observed {
                return Ok(());
            }
            match running.session.observe_disconnect(service) {
                DisconnectObservation::Connected => Ok(()),
                DisconnectObservation::CancellationDelivered => {
                    running.disconnect_observed = true;
                    Ok(())
                }
                DisconnectObservation::CancellationUnavailable => {
                    if !running.session.is_active_in(service) {
                        return Err(AuthDaemonError::Scheduler);
                    }
                    running.disconnect_observed = true;
                    Ok(())
                }
            }
        }
        ActiveRun::Standard(_) => Ok(()),
    }
}

fn poll_active_worker(
    active: &mut Option<ActiveRun>,
    standard_connections: &mut Vec<TimedStandardConnection>,
    replies: &mut Vec<TimedReply>,
    service: &mut BrokerServiceScheduler,
    now: Duration,
) -> Result<(), AuthDaemonError> {
    let Some(running) = active.take() else {
        return Ok(());
    };
    match running {
        ActiveRun::Direct(mut running) => match running.worker.poll() {
            WorkerPoll::Pending(worker) => {
                running.worker = worker;
                *active = Some(ActiveRun::Direct(running));
                Ok(())
            }
            WorkerPoll::Completed(completion) => {
                if !completion.belongs_to(running.session.authentication()) {
                    let _ = running.session.worker_lost(service);
                    return Err(AuthDaemonError::WorkerLost);
                }
                // Live workers own their exact match-scoped presentation. By
                // completion, terminal Mesa cancellation, feedback, overlay
                // removal, ACM release, SEP release, BridgeXPC close, and relay
                // recovery have already occurred in that order.
                let reply = running.session.finish(service, &completion, now);
                if !running.disconnect_observed {
                    queue_reply(replies, reply, now);
                }
                Ok(())
            }
            WorkerPoll::Lost => {
                let _ = running.session.worker_lost(service);
                Err(AuthDaemonError::WorkerLost)
            }
        },
        ActiveRun::Standard(running) => {
            let mut running = *running;
            if running.connection.has_pending_reply() {
                *active = Some(ActiveRun::Standard(Box::new(running)));
                return Ok(());
            }
            match running.worker.poll() {
                StandardWorkerPoll::Pending(worker) => {
                    running.worker = worker;
                    *active = Some(ActiveRun::Standard(Box::new(running)));
                    Ok(())
                }
                StandardWorkerPoll::Progress(worker, progress) => {
                    running.worker = worker;
                    if !running.disconnect_observed {
                        running
                            .connection
                            .queue_worker_progress(&running.job, progress)
                            .map_err(map_standard_socket_error)?;
                        running.reply_deadline = Some(now.saturating_add(REPLY_TIMEOUT));
                    }
                    *active = Some(ActiveRun::Standard(Box::new(running)));
                    Ok(())
                }
                StandardWorkerPoll::Completed(completion) => {
                    let event = running
                        .connection
                        .finish_worker(service, &completion, now)
                        .map_err(map_standard_socket_error)?;
                    if !matches!(event, StandardSocketEvent::ReplyQueued) {
                        return Err(AuthDaemonError::Scheduler);
                    }
                    if !running.disconnect_observed {
                        standard_connections.push(TimedStandardConnection {
                            connection: running.connection,
                            request_deadline: None,
                            reply_deadline: Some(now.saturating_add(REPLY_TIMEOUT)),
                        });
                    }
                    Ok(())
                }
                StandardWorkerPoll::Lost => {
                    let _ = running.connection.worker_lost(service);
                    Err(AuthDaemonError::WorkerLost)
                }
            }
        }
    }
}

fn queue_reply(replies: &mut Vec<TimedReply>, reply: PendingBrokerReply<OwnedFd>, now: Duration) {
    replies.push(TimedReply {
        reply,
        deadline: now.saturating_add(REPLY_TIMEOUT),
    });
}

fn flush_standard_replies(connections: &mut Vec<TimedStandardConnection>, now: Duration) {
    connections.retain_mut(|timed| {
        if !timed.connection.has_pending_reply() {
            return true;
        }
        if timed.reply_deadline.is_some_and(|deadline| now >= deadline) {
            return false;
        }
        match timed.connection.flush_reply() {
            Ok(true) => {
                timed.reply_deadline = None;
                true
            }
            Ok(false) => true,
            Err(_) => false,
        }
    });
}

fn flush_active_standard_reply(
    active: &mut Option<ActiveRun>,
    service: &mut BrokerServiceScheduler,
    now: Duration,
) -> Result<(), AuthDaemonError> {
    let Some(ActiveRun::Standard(running)) = active.as_mut() else {
        return Ok(());
    };
    if running.disconnect_observed || !running.connection.has_pending_reply() {
        return Ok(());
    }
    if running
        .reply_deadline
        .is_some_and(|deadline| now >= deadline)
    {
        return disconnect_standard_run(running, service);
    }
    match running.connection.flush_reply() {
        Ok(true) => {
            running.reply_deadline = None;
            Ok(())
        }
        Ok(false) => Ok(()),
        Err(_) => disconnect_standard_run(running, service),
    }
}

fn cancel_or_await_completion(
    running: &ActiveRun,
    service: &mut BrokerServiceScheduler,
) -> Result<(), AuthDaemonError> {
    let owned = match running {
        ActiveRun::Direct(running) => {
            running.session.deadline_expired(service) || running.session.is_active_in(service)
        }
        ActiveRun::Standard(running) => {
            running.connection.deadline_expired(service) || running.connection.is_active_in(service)
        }
    };
    // A mutation cutoff can reject delivery while durable work still owns the
    // lease. Await its exact completion; a lost worker remains fatal.
    if owned {
        Ok(())
    } else {
        Err(AuthDaemonError::Scheduler)
    }
}

fn disconnect_standard_run(
    running: &mut ActiveStandardRun,
    service: &mut BrokerServiceScheduler,
) -> Result<(), AuthDaemonError> {
    if !running.connection.client_disconnected(service) && !running.connection.is_active_in(service)
    {
        return Err(AuthDaemonError::Scheduler);
    }
    running.connection.discard_reply();
    running.reply_deadline = None;
    running.disconnect_observed = true;
    Ok(())
}

fn flush_replies(replies: &mut Vec<TimedReply>, now: Duration) {
    let mut pending = Vec::with_capacity(replies.len());
    while let Some(timed) = replies.pop() {
        if now >= timed.deadline {
            continue;
        }
        if let Ok(BrokerReplyProgress::Pending(reply)) = timed.reply.try_send() {
            pending.push(TimedReply {
                reply,
                deadline: timed.deadline,
            });
        }
    }
    *replies = pending;
}

fn map_standard_socket_error(_: StandardSocketError) -> AuthDaemonError {
    AuthDaemonError::Listener
}

fn map_socket_error(_: BrokerSocketError) -> AuthDaemonError {
    AuthDaemonError::Listener
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::SyncSender;
    use t1_bridge::match_workflow::MatchOutcome;

    use crate::auth_protocol::{
        AUTHENTICATE_REQUEST, AccessPolicy, CANCEL_REQUEST, ENROLL_REQUEST, PeerAddressFamily,
        PeerMetadata, Response,
    };
    use crate::auth_scheduler::{ScheduledDispatch, ScheduledStandardDispatch};
    use crate::standard_connection::StandardConnection;
    use crate::standard_fingerprint_protocol::{
        FingerLabel, IdentityId, ServerMessage, TerminalOutcome, Username,
    };
    use crate::standard_operation_authority::{ResolvedStandardAccount, ResolvedStandardOperation};

    const OWNER_UID: u32 = 42_000;

    fn peer(user_id: u32) -> PeerMetadata {
        PeerMetadata {
            address_family: PeerAddressFamily::Local,
            user_id,
            group_id: 42_001,
        }
    }

    fn service() -> BrokerServiceScheduler {
        BrokerServiceScheduler::new(Duration::ZERO, IDLE_TIMEOUT).unwrap()
    }

    fn policy() -> AccessPolicy {
        AccessPolicy::new(OWNER_UID).unwrap()
    }

    fn closed_transport() -> OwnedFd {
        let (socket, peer) = t1_platform::seqpacket::pair_for_test().unwrap();
        drop(peer);
        socket
    }

    fn direct_run(
        service: &mut BrokerServiceScheduler,
        cutoff: bool,
    ) -> (Option<ActiveRun>, SyncSender<()>) {
        let ScheduledDispatch::Start(scheduled) =
            service.dispatch(peer(OWNER_UID), policy(), ENROLL_REQUEST, Duration::ZERO)
        else {
            panic!("synthetic enrollment starts")
        };
        if cutoff {
            assert!(scheduled.authentication().close_cancellation());
        }
        let completion = scheduled
            .authentication()
            .completion_for_worker(Ok(MatchOutcome::Matched));
        let (resume, gate) = sync_channel(1);
        let (sender, receiver) = sync_channel(1);
        let handle = thread::spawn(move || {
            gate.recv().unwrap();
            sender.send(completion).unwrap();
        });
        (
            Some(ActiveRun::Direct(ActiveDirectRun {
                session: ActiveBrokerSocketSession::for_test(closed_transport(), scheduled),
                worker: WorkerThread { receiver, handle },
                disconnect_observed: false,
            })),
            resume,
        )
    }

    fn standard_run(
        service: &mut BrokerServiceScheduler,
        cutoff: bool,
    ) -> (Option<ActiveRun>, SyncSender<()>) {
        let username = Username::new("synthetic-owner").unwrap();
        let account = ResolvedStandardAccount::new(&username, &username, OWNER_UID).unwrap();
        let ScheduledStandardDispatch::Start(scheduled) = service.dispatch_standard(
            peer(0),
            Some(policy()),
            ResolvedStandardOperation::Enroll {
                account,
                finger: FingerLabel::RightIndex,
            },
            Duration::ZERO,
        ) else {
            panic!("synthetic standard enrollment starts")
        };
        let (connection, job) = StandardConnection::for_test(
            peer(0),
            StandardConnectionConfig::new(6).unwrap(),
            scheduled,
        );
        if cutoff {
            assert!(job.operation().close_cancellation());
        }
        let completion = job.completion(ServerMessage::Terminal(TerminalOutcome::Enrolled(
            IdentityId::new([0x21; 16]).unwrap(),
        )));
        let (resume, gate) = sync_channel(1);
        let (sender, receiver) = sync_channel(1);
        let handle = thread::spawn(move || {
            gate.recv().unwrap();
            sender
                .send(StandardWorkerEvent::Progress(
                    EnrollProgress::new(2, 6).unwrap(),
                ))
                .unwrap();
            sender
                .send(StandardWorkerEvent::Completed(completion))
                .unwrap();
        });
        (
            Some(ActiveRun::Standard(Box::new(ActiveStandardRun {
                connection: StandardSocketConnection::for_test(closed_transport(), connection),
                job,
                worker: StandardWorkerThread { receiver, handle },
                disconnect_observed: false,
                reply_deadline: None,
            }))),
            resume,
        )
    }

    fn finish_disconnected_run(
        active: &mut Option<ActiveRun>,
        scheduler: &mut BrokerServiceScheduler,
        resume: &SyncSender<()>,
    ) {
        assert!(matches!(
            scheduler.dispatch(
                peer(OWNER_UID),
                policy(),
                AUTHENTICATE_REQUEST,
                Duration::ZERO
            ),
            ScheduledDispatch::Reply(Response::Busy)
        ));
        resume.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut pending = Vec::new();
        let mut replies = Vec::new();
        while active.is_some() {
            assert!(
                Instant::now() < deadline,
                "exact worker completion must drain"
            );
            poll_active_worker(
                active,
                &mut pending,
                &mut replies,
                scheduler,
                Duration::ZERO,
            )
            .unwrap();
            thread::yield_now();
        }
        assert!(
            pending.is_empty() && replies.is_empty(),
            "no reply retained for disconnected peer"
        );
        assert!(matches!(
            scheduler.dispatch(
                peer(OWNER_UID),
                policy(),
                AUTHENTICATE_REQUEST,
                Duration::ZERO
            ),
            ScheduledDispatch::Start(_)
        ));
    }

    #[test]
    fn direct_disconnect_and_deadline_preserve_exact_completion_across_cutoff() {
        for cutoff in [false, true] {
            let mut scheduler = service();
            let (mut active, resume) = direct_run(&mut scheduler, cutoff);
            cancel_or_await_completion(active.as_ref().unwrap(), &mut scheduler).unwrap();
            observe_active_disconnect(&mut active, &mut scheduler).unwrap();
            let Some(ActiveRun::Direct(running)) = active.as_ref() else {
                unreachable!()
            };
            assert!(running.disconnect_observed);
            assert_eq!(running.session.authentication().is_cancelled(), !cutoff);
            finish_disconnected_run(&mut active, &mut scheduler, &resume);
        }
    }

    #[test]
    fn standard_disconnect_and_reply_failures_drain_worker_across_cutoff() {
        for cutoff in [false, true] {
            for trigger in 0..3 {
                let mut scheduler = service();
                let (mut active, resume) = standard_run(&mut scheduler, cutoff);
                cancel_or_await_completion(active.as_ref().unwrap(), &mut scheduler).unwrap();
                if trigger == 0 {
                    let unused_store = EnrollmentOwnerStore::new("/synthetic-unused-owner-store");
                    process_active_standard_control(
                        &mut active,
                        &mut scheduler,
                        &unused_store,
                        Duration::ZERO,
                    )
                    .unwrap();
                } else {
                    let Some(ActiveRun::Standard(running)) = active.as_mut() else {
                        unreachable!()
                    };
                    running
                        .connection
                        .queue_worker_progress(&running.job, EnrollProgress::new(1, 6).unwrap())
                        .unwrap();
                    running.reply_deadline = Some(if trigger == 1 {
                        Duration::ZERO
                    } else {
                        REPLY_TIMEOUT
                    });
                    flush_active_standard_reply(&mut active, &mut scheduler, Duration::ZERO)
                        .unwrap();
                }
                let Some(ActiveRun::Standard(running)) = active.as_ref() else {
                    unreachable!()
                };
                assert!(running.disconnect_observed);
                assert!(!running.connection.has_pending_reply());
                assert!(running.reply_deadline.is_none());
                assert_eq!(running.job.is_cancelled(), !cutoff);
                finish_disconnected_run(&mut active, &mut scheduler, &resume);
            }
        }
    }

    #[test]
    fn unavailable_cancellation_cannot_mask_foreign_scheduler_authority() {
        for standard in [false, true] {
            let mut scheduler = service();
            let (mut active, resume) = if standard {
                standard_run(&mut scheduler, true)
            } else {
                direct_run(&mut scheduler, true)
            };
            let mut foreign = service();
            assert_eq!(
                cancel_or_await_completion(active.as_ref().unwrap(), &mut foreign),
                Err(AuthDaemonError::Scheduler)
            );
            match active.as_mut().unwrap() {
                ActiveRun::Direct(_) => assert_eq!(
                    observe_active_disconnect(&mut active, &mut foreign),
                    Err(AuthDaemonError::Scheduler)
                ),
                ActiveRun::Standard(running) => assert_eq!(
                    disconnect_standard_run(running, &mut foreign),
                    Err(AuthDaemonError::Scheduler)
                ),
            }
            match active.as_mut().unwrap() {
                ActiveRun::Direct(_) => {
                    observe_active_disconnect(&mut active, &mut scheduler).unwrap();
                }
                ActiveRun::Standard(running) => {
                    disconnect_standard_run(running, &mut scheduler).unwrap();
                }
            }
            finish_disconnected_run(&mut active, &mut scheduler, &resume);
        }
    }

    fn poll_worker(mut worker: WorkerThread) -> WorkerPoll {
        for _ in 0..10_000 {
            match worker.poll() {
                WorkerPoll::Pending(pending) => {
                    worker = pending;
                    thread::yield_now();
                }
                result => return result,
            }
        }
        panic!("synthetic worker did not finish")
    }

    #[test]
    fn activation_requires_two_exact_systemd_descriptors() {
        assert!(parse_activation_pair(&std::process::id().to_string(), "2").is_ok());
        for (pid, descriptors) in [("", "2"), ("01", "2"), ("1", "0"), ("1", "1")] {
            assert!(matches!(
                parse_activation_pair(pid, descriptors),
                Err(AuthDaemonError::Activation)
            ));
        }
    }

    #[test]
    fn activation_accepts_either_exact_named_listener_order() {
        assert_eq!(
            parse_listener_order("t1-touchid-auth.socket:t1bridge-fingerprint.socket"),
            Ok(ListenerOrder::DirectFirst)
        );
        assert_eq!(
            parse_listener_order("t1bridge-fingerprint.socket:t1-touchid-auth.socket"),
            Ok(ListenerOrder::StandardFirst)
        );
    }

    #[test]
    fn activation_rejects_missing_duplicate_or_extra_listener_names() {
        for names in [
            "",
            "t1-touchid-auth.socket",
            "t1-touchid-auth.socket:t1-touchid-auth.socket",
            "t1bridge-fingerprint.socket:t1bridge-fingerprint.socket",
            "t1bridge-fingerprint.socket:t1-touchid-auth.socket:extra.socket",
        ] {
            assert_eq!(
                parse_listener_order(names),
                Err(AuthDaemonError::Activation)
            );
        }
    }

    #[test]
    fn one_worker_completion_retains_exact_token_and_releases_the_slot() {
        let mut service = service();
        let ScheduledDispatch::Start(scheduled) = service.dispatch(
            peer(OWNER_UID),
            policy(),
            AUTHENTICATE_REQUEST,
            Duration::ZERO,
        ) else {
            panic!("operation starts")
        };
        let worker: Arc<dyn BrokerWorker> = Arc::new(|active: ActiveAuthentication| {
            active.completion_for_worker(Ok(MatchOutcome::Matched))
        });
        let worker = WorkerThread::spawn(worker, scheduled.authentication()).unwrap();
        let WorkerPoll::Completed(completion) = poll_worker(worker) else {
            panic!("worker completion is delivered")
        };
        assert!(completion.belongs_to(scheduled.authentication()));
        assert_eq!(
            service.finish(&scheduled, &completion, Duration::from_secs(1)),
            Response::Okay
        );
        assert!(matches!(
            service.dispatch(
                peer(OWNER_UID),
                policy(),
                AUTHENTICATE_REQUEST,
                Duration::from_secs(1)
            ),
            ScheduledDispatch::Start(_)
        ));
    }

    #[test]
    fn root_cancel_and_disconnect_win_while_new_work_is_busy() {
        let mut service = service();
        let ScheduledDispatch::Start(scheduled) = service.dispatch(
            peer(OWNER_UID),
            policy(),
            AUTHENTICATE_REQUEST,
            Duration::ZERO,
        ) else {
            panic!("operation starts")
        };
        let worker: Arc<dyn BrokerWorker> = Arc::new(|active: ActiveAuthentication| {
            while !active.is_cancelled() {
                thread::yield_now();
            }
            active.completion_for_worker(Ok(MatchOutcome::Cancelled))
        });
        let worker = WorkerThread::spawn(worker, scheduled.authentication()).unwrap();
        assert!(matches!(
            service.dispatch(
                peer(OWNER_UID),
                policy(),
                AUTHENTICATE_REQUEST,
                Duration::ZERO
            ),
            ScheduledDispatch::Reply(Response::Busy)
        ));
        assert!(service.client_disconnected(&scheduled));
        assert!(matches!(
            service.dispatch(peer(0), policy(), CANCEL_REQUEST, Duration::ZERO),
            ScheduledDispatch::Reply(Response::Okay)
        ));
        let WorkerPoll::Completed(completion) = poll_worker(worker) else {
            panic!("cancelled worker reports completion")
        };
        assert_eq!(
            service.finish(&scheduled, &completion, Duration::from_secs(1)),
            Response::Failure
        );
    }

    #[test]
    fn lost_worker_poisoning_terminates_the_service() {
        let mut service = service();
        let ScheduledDispatch::Start(scheduled) = service.dispatch(
            peer(OWNER_UID),
            policy(),
            AUTHENTICATE_REQUEST,
            Duration::ZERO,
        ) else {
            panic!("operation starts")
        };
        let worker: Arc<dyn BrokerWorker> = Arc::new(|_: ActiveAuthentication| {
            panic!("synthetic worker loss");
        });
        let worker = WorkerThread::spawn(worker, scheduled.authentication()).unwrap();
        assert!(matches!(poll_worker(worker), WorkerPoll::Lost));
        assert!(service.worker_lost(&scheduled));
        assert_eq!(
            service.decide(Duration::ZERO, false),
            LifecycleDecision::Terminate
        );
    }
}
