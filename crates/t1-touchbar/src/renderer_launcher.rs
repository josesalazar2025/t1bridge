//! Unprivileged selected-renderer launch and one-shot default fallback.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};

/// The sole renderer selection path below an already-resolved XDG config home.
#[must_use]
pub fn renderer_selection_path(xdg_config_home: &Path) -> PathBuf {
    xdg_config_home.join("t1bridge/renderer")
}

/// Resolves the XDG configuration home from already-read environment values.
///
/// Empty or relative `XDG_CONFIG_HOME` values are ignored. An absolute HOME
/// falls back to its `.config` child. No process environment is read here.
#[must_use]
pub fn resolve_xdg_config_home(
    xdg_config_home: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Option<PathBuf> {
    xdg_config_home
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            home.filter(|value| !value.is_empty())
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .map(|path| path.join(".config"))
        })
}

/// Why the launcher replaced a selected renderer with the packaged default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RendererFallbackReason {
    /// The selected path could not be executed.
    SelectionUnavailable,
    /// The selected process was observed to exit.
    SelectionExited,
}

/// Process operations owned by the unprivileged renderer launcher.
pub trait RendererProcessRuntime {
    type Child;
    type Exit;
    type Error;

    /// Starts the executable at `path` without adding arguments.
    ///
    /// # Errors
    ///
    /// Returns the runtime's process-start error.
    fn spawn(&mut self, path: &Path) -> Result<Self::Child, Self::Error>;

    /// Waits for one previously started renderer.
    ///
    /// # Errors
    ///
    /// Returns the runtime's process-supervision error.
    fn wait(&mut self, child: Self::Child) -> Result<Self::Exit, Self::Error>;
}

/// Standard-library production process runtime.
#[derive(Clone, Copy, Debug, Default)]
pub struct StdRendererProcessRuntime;

impl RendererProcessRuntime for StdRendererProcessRuntime {
    type Child = Child;
    type Exit = ExitStatus;
    type Error = std::io::Error;

    fn spawn(&mut self, path: &Path) -> Result<Self::Child, Self::Error> {
        Command::new(path).spawn()
    }

    fn wait(&mut self, mut child: Self::Child) -> Result<Self::Exit, Self::Error> {
        child.wait()
    }
}

/// Best-effort user notification when selection falls back.
pub trait RendererFallbackNotifier {
    type Error;

    /// Emits the one fallback notification.
    ///
    /// # Errors
    ///
    /// Returns the notification transport error. The launcher deliberately
    /// ignores it so a broken notifier cannot suppress the default renderer.
    fn notify(&mut self, reason: RendererFallbackReason) -> Result<(), Self::Error>;
}

/// Runs the selected renderer once, then the packaged default once after a
/// selected-renderer spawn failure or observed exit.
///
/// Selection and default paths are supplied by the unprivileged process entry
/// point. This function never reads, rewrites, retries, or registers the user
/// selection. Notification failure cannot prevent the one allowed fallback.
///
/// # Errors
///
/// Returns a selected-renderer wait error without starting another process,
/// because that error does not prove the selected child has exited. Also
/// returns the packaged default's spawn or wait error. Selected spawn errors
/// and notifier errors cause fallback and are deliberately not returned.
pub fn run_selected_or_default<Runtime, Notifier>(
    selection_path: &Path,
    packaged_default_path: &Path,
    runtime: &mut Runtime,
    notifier: &mut Notifier,
) -> Result<Runtime::Exit, Runtime::Error>
where
    Runtime: RendererProcessRuntime,
    Notifier: RendererFallbackNotifier,
{
    let reason = selected_fallback_reason(selection_path, runtime)?;

    let _ = notifier.notify(reason);
    let default = runtime.spawn(packaged_default_path)?;
    runtime.wait(default)
}

/// Runs the selected renderer once and invokes the in-process built-in after
/// an unavailable selection or observed exit.
///
/// A notifier failure cannot suppress the built-in. An uncertain wait failure
/// is returned without invoking it because the selected child may still run.
///
/// # Errors
///
/// Returns the selected renderer's wait error.
pub fn run_selected_or_builtin<Runtime, Notifier, Builtin, Output>(
    selection_path: &Path,
    runtime: &mut Runtime,
    notifier: &mut Notifier,
    builtin: Builtin,
) -> Result<Output, Runtime::Error>
where
    Runtime: RendererProcessRuntime,
    Notifier: RendererFallbackNotifier,
    Builtin: FnOnce() -> Output,
{
    let reason = selected_fallback_reason(selection_path, runtime)?;
    let _ = notifier.notify(reason);
    Ok(builtin())
}

fn selected_fallback_reason<Runtime>(
    selection_path: &Path,
    runtime: &mut Runtime,
) -> Result<RendererFallbackReason, Runtime::Error>
where
    Runtime: RendererProcessRuntime,
{
    match runtime.spawn(selection_path) {
        Ok(child) => {
            runtime.wait(child)?;
            Ok(RendererFallbackReason::SelectionExited)
        }
        Err(_) => Ok(RendererFallbackReason::SelectionUnavailable),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    const SELECTED: &str = "synthetic/config/t1bridge/renderer";
    const DEFAULT: &str = "synthetic/package/t1bridge-renderer";
    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "t1bridge-renderer-selection-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create test directory");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FakeError {
        SelectedSpawn,
        SelectedWait,
        DefaultSpawn,
        DefaultWait,
    }

    #[derive(Debug, Eq, PartialEq)]
    enum Call {
        Spawn(PathBuf),
        Wait(u8),
    }

    struct FakeRuntime {
        spawns: VecDeque<Result<u8, FakeError>>,
        waits: VecDeque<Result<u8, FakeError>>,
        calls: Vec<Call>,
    }

    impl FakeRuntime {
        fn new(
            spawns: impl IntoIterator<Item = Result<u8, FakeError>>,
            waits: impl IntoIterator<Item = Result<u8, FakeError>>,
        ) -> Self {
            Self {
                spawns: spawns.into_iter().collect(),
                waits: waits.into_iter().collect(),
                calls: Vec::new(),
            }
        }

        fn assert_exhausted(&self) {
            assert!(self.spawns.is_empty());
            assert!(self.waits.is_empty());
        }
    }

    impl RendererProcessRuntime for FakeRuntime {
        type Child = u8;
        type Exit = u8;
        type Error = FakeError;

        fn spawn(&mut self, path: &Path) -> Result<Self::Child, Self::Error> {
            self.calls.push(Call::Spawn(path.to_path_buf()));
            self.spawns.pop_front().expect("planned spawn outcome")
        }

        fn wait(&mut self, child: Self::Child) -> Result<Self::Exit, Self::Error> {
            self.calls.push(Call::Wait(child));
            self.waits.pop_front().expect("planned wait outcome")
        }
    }

    #[derive(Default)]
    struct FakeNotifier {
        reasons: Vec<RendererFallbackReason>,
        fail: bool,
    }

    impl RendererFallbackNotifier for FakeNotifier {
        type Error = ();

        fn notify(&mut self, reason: RendererFallbackReason) -> Result<(), Self::Error> {
            self.reasons.push(reason);
            if self.fail { Err(()) } else { Ok(()) }
        }
    }

    fn run(runtime: &mut FakeRuntime, notifier: &mut FakeNotifier) -> Result<u8, FakeError> {
        run_selected_or_default(Path::new(SELECTED), Path::new(DEFAULT), runtime, notifier)
    }

    #[test]
    fn selection_path_is_fixed_below_the_resolved_config_home() {
        assert_eq!(
            renderer_selection_path(Path::new("synthetic/config")),
            Path::new(SELECTED)
        );
    }

    #[test]
    fn xdg_resolution_ignores_relative_values_and_uses_absolute_home_fallback() {
        assert_eq!(
            resolve_xdg_config_home(Some(OsStr::new("/synthetic/config")), None),
            Some(PathBuf::from("/synthetic/config"))
        );
        assert_eq!(
            resolve_xdg_config_home(
                Some(OsStr::new("relative/config")),
                Some(OsStr::new("/synthetic/home"))
            ),
            Some(PathBuf::from("/synthetic/home/.config"))
        );
        assert_eq!(
            resolve_xdg_config_home(Some(OsStr::new("")), Some(OsStr::new("relative/home"))),
            None
        );
    }

    #[test]
    fn selected_renderer_falls_back_to_in_process_builtin_exactly_once() {
        let mut runtime = FakeRuntime::new([Ok(1)], [Ok(10)]);
        let mut notifier = FakeNotifier::default();
        let mut calls = 0;

        assert_eq!(
            run_selected_or_builtin(Path::new(SELECTED), &mut runtime, &mut notifier, || {
                calls += 1;
                42
            }),
            Ok(42)
        );
        assert_eq!(calls, 1);
        assert_eq!(notifier.reasons, [RendererFallbackReason::SelectionExited]);
    }

    #[test]
    fn unavailable_renderer_also_starts_in_process_builtin_exactly_once() {
        let mut runtime = FakeRuntime::new([Err(FakeError::SelectedSpawn)], []);
        let mut notifier = FakeNotifier::default();
        let mut calls = 0;

        assert_eq!(
            run_selected_or_builtin(Path::new(SELECTED), &mut runtime, &mut notifier, || {
                calls += 1;
                24
            }),
            Ok(24)
        );
        assert_eq!(calls, 1);
        assert_eq!(
            notifier.reasons,
            [RendererFallbackReason::SelectionUnavailable]
        );
    }

    #[test]
    fn non_executable_selection_falls_back_without_touching_the_file() {
        let directory = TestDirectory::new();
        let selection = directory.0.join("renderer");
        let contents = b"synthetic renderer selection\n";
        fs::write(&selection, contents).expect("write selected renderer");
        fs::set_permissions(&selection, fs::Permissions::from_mode(0o640))
            .expect("make selection non-executable");
        let before = fs::metadata(&selection).expect("inspect selection before fallback");

        let mut runtime = StdRendererProcessRuntime;
        let mut notifier = FakeNotifier::default();
        let output = run_selected_or_builtin(&selection, &mut runtime, &mut notifier, || 91)
            .expect("fall back to built-in");
        assert_eq!(output, 91);

        let after = fs::metadata(&selection).expect("inspect selection after fallback");
        assert_eq!(
            fs::read(&selection).expect("read preserved selection"),
            contents
        );
        assert_eq!(after.ino(), before.ino());
        assert_eq!(after.mode(), before.mode());
        assert_eq!(after.len(), before.len());
        assert_eq!(
            notifier.reasons,
            [RendererFallbackReason::SelectionUnavailable]
        );
    }

    #[test]
    fn uncertain_selected_wait_never_starts_in_process_builtin() {
        let mut runtime = FakeRuntime::new([Ok(1)], [Err(FakeError::SelectedWait)]);
        let mut notifier = FakeNotifier::default();
        let mut calls = 0;

        assert_eq!(
            run_selected_or_builtin(Path::new(SELECTED), &mut runtime, &mut notifier, || {
                calls += 1;
            }),
            Err(FakeError::SelectedWait)
        );
        assert_eq!(calls, 0);
        assert!(notifier.reasons.is_empty());
    }

    #[test]
    fn selected_exit_notifies_and_runs_the_default_exactly_once() {
        let mut runtime = FakeRuntime::new([Ok(1), Ok(2)], [Ok(10), Ok(20)]);
        let mut notifier = FakeNotifier::default();

        assert_eq!(run(&mut runtime, &mut notifier), Ok(20));
        assert_eq!(
            runtime.calls,
            [
                Call::Spawn(PathBuf::from(SELECTED)),
                Call::Wait(1),
                Call::Spawn(PathBuf::from(DEFAULT)),
                Call::Wait(2),
            ]
        );
        runtime.assert_exhausted();
        assert_eq!(notifier.reasons, [RendererFallbackReason::SelectionExited]);
    }

    #[test]
    fn unavailable_selection_falls_back_without_a_selection_wait() {
        let mut runtime = FakeRuntime::new([Err(FakeError::SelectedSpawn), Ok(2)], [Ok(20)]);
        let mut notifier = FakeNotifier::default();

        assert_eq!(run(&mut runtime, &mut notifier), Ok(20));
        assert_eq!(
            runtime.calls,
            [
                Call::Spawn(PathBuf::from(SELECTED)),
                Call::Spawn(PathBuf::from(DEFAULT)),
                Call::Wait(2),
            ]
        );
        runtime.assert_exhausted();
        assert_eq!(
            notifier.reasons,
            [RendererFallbackReason::SelectionUnavailable]
        );
    }

    #[test]
    fn uncertain_selection_wait_failure_never_starts_a_second_renderer() {
        let mut runtime = FakeRuntime::new([Ok(1)], [Err(FakeError::SelectedWait)]);
        let mut notifier = FakeNotifier::default();

        assert_eq!(
            run(&mut runtime, &mut notifier),
            Err(FakeError::SelectedWait)
        );
        assert_eq!(
            runtime.calls,
            [Call::Spawn(PathBuf::from(SELECTED)), Call::Wait(1)]
        );
        runtime.assert_exhausted();
        assert!(notifier.reasons.is_empty());
    }

    #[test]
    fn notification_failure_does_not_prevent_the_default() {
        let mut runtime = FakeRuntime::new([Err(FakeError::SelectedSpawn), Ok(2)], [Ok(20)]);
        let mut notifier = FakeNotifier {
            fail: true,
            ..FakeNotifier::default()
        };

        assert_eq!(run(&mut runtime, &mut notifier), Ok(20));
        runtime.assert_exhausted();
        assert_eq!(notifier.reasons.len(), 1);
    }

    #[test]
    fn default_spawn_failure_is_returned_without_retry() {
        let mut runtime = FakeRuntime::new(
            [Err(FakeError::SelectedSpawn), Err(FakeError::DefaultSpawn)],
            [],
        );
        let mut notifier = FakeNotifier::default();

        assert_eq!(
            run(&mut runtime, &mut notifier),
            Err(FakeError::DefaultSpawn)
        );
        runtime.assert_exhausted();
        assert_eq!(notifier.reasons.len(), 1);
    }

    #[test]
    fn default_wait_failure_is_returned_without_retry() {
        let mut runtime = FakeRuntime::new(
            [Err(FakeError::SelectedSpawn), Ok(2)],
            [Err(FakeError::DefaultWait)],
        );
        let mut notifier = FakeNotifier::default();

        assert_eq!(
            run(&mut runtime, &mut notifier),
            Err(FakeError::DefaultWait)
        );
        runtime.assert_exhausted();
        assert_eq!(notifier.reasons.len(), 1);
    }
}
