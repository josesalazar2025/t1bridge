use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use t1_touchbar::builtin_renderer;
use t1_touchbar::desktop_provider::{
    PROVIDER_ENVIRONMENT, RendererFallback, notify_renderer_fallback, resolve_provider_path,
};
use t1_touchbar::renderer_launcher::{
    RendererFallbackNotifier, RendererFallbackReason, StdRendererProcessRuntime,
    renderer_selection_path, resolve_xdg_config_home, run_selected_or_builtin,
};

struct DesktopFallbackNotifier {
    provider_path: Option<PathBuf>,
}

impl RendererFallbackNotifier for DesktopFallbackNotifier {
    type Error = ();

    fn notify(&mut self, reason: RendererFallbackReason) -> Result<(), Self::Error> {
        let provider_reason = match reason {
            RendererFallbackReason::SelectionUnavailable => RendererFallback::SelectionUnavailable,
            RendererFallbackReason::SelectionExited => RendererFallback::SelectionExited,
        };
        if self
            .provider_path
            .as_deref()
            .is_some_and(|path| notify_renderer_fallback(path, provider_reason))
        {
            return Ok(());
        }
        let diagnostic = match reason {
            RendererFallbackReason::SelectionUnavailable => {
                "selected renderer unavailable; using built-in"
            }
            RendererFallbackReason::SelectionExited => "selected renderer exited; using built-in",
        };
        eprintln!("t1-touchbar: {diagnostic}");
        Ok(())
    }
}

fn main() -> ExitCode {
    if run().is_ok() {
        ExitCode::SUCCESS
    } else {
        eprintln!("t1-touchbar: selected renderer supervision failed");
        ExitCode::FAILURE
    }
}

fn run() -> Result<(), ()> {
    let xdg = env::var_os("XDG_CONFIG_HOME");
    let home = env::var_os("HOME");
    let provider_value = env::var_os(PROVIDER_ENVIRONMENT);
    let provider_path = resolve_provider_path(provider_value.as_deref());
    let mut notifier = DesktopFallbackNotifier {
        provider_path: provider_path.clone(),
    };
    let Some(config_home) = resolve_xdg_config_home(xdg.as_deref(), home.as_deref()) else {
        let _ = notifier.notify(RendererFallbackReason::SelectionUnavailable);
        builtin_renderer::run_forever(provider_path.as_deref());
        return Ok(());
    };
    let selection = renderer_selection_path(&config_home);
    let mut runtime = StdRendererProcessRuntime;
    run_selected_or_builtin(&selection, &mut runtime, &mut notifier, || {
        builtin_renderer::run_forever(provider_path.as_deref());
    })
    .map_err(|_| ())
}
