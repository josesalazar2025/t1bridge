use std::time::Duration;

use crate::digitizer::{DigitizerReport, DisplayContact, DisplayDimensions};

#[derive(Clone, Debug, PartialEq)]
pub struct InputFrame {
    pub timestamp: Duration,
    pub fn_pressed: bool,
    pub contacts: Vec<DisplayContact>,
}

#[derive(Debug)]
pub struct InputState {
    dimensions: DisplayDimensions,
    fn_pressed: bool,
    contacts: Vec<DisplayContact>,
}

impl InputState {
    #[must_use]
    pub fn new(dimensions: DisplayDimensions, initial_fn_pressed: bool) -> Self {
        Self {
            dimensions,
            fn_pressed: initial_fn_pressed,
            contacts: Vec::new(),
        }
    }

    #[must_use]
    pub fn ingest_touch(&mut self, timestamp: Duration, report: &DigitizerReport) -> InputFrame {
        self.contacts = report.scaled_contacts(self.dimensions);
        self.frame(timestamp)
    }

    #[must_use]
    pub fn set_fn_pressed(&mut self, timestamp: Duration, fn_pressed: bool) -> Option<InputFrame> {
        if self.fn_pressed == fn_pressed {
            return None;
        }
        self.fn_pressed = fn_pressed;
        Some(self.frame(timestamp))
    }

    #[must_use]
    pub fn touch_idle(&mut self, timestamp: Duration) -> Option<InputFrame> {
        if self.contacts.is_empty() {
            return None;
        }
        self.contacts.clear();
        Some(self.frame(timestamp))
    }

    fn frame(&self, timestamp: Duration) -> InputFrame {
        InputFrame {
            timestamp,
            fn_pressed: self.fn_pressed,
            contacts: self.contacts.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digitizer::{DIGITIZER_PAYLOAD_SIZE, parse_digitizer_payload};

    fn report(contact: Option<[u8; 4]>) -> DigitizerReport {
        let mut payload = [0_u8; DIGITIZER_PAYLOAD_SIZE];
        if let Some(contact) = contact {
            payload[..4].copy_from_slice(&contact);
        }
        parse_digitizer_payload(&payload).expect("valid synthetic payload")
    }

    fn state() -> InputState {
        InputState::new(
            DisplayDimensions::new(101, 51).expect("valid dimensions"),
            false,
        )
    }

    #[test]
    fn touch_report_emits_scaled_contacts_with_current_fn_state() {
        let mut state = InputState::new(
            DisplayDimensions::new(101, 51).expect("valid dimensions"),
            true,
        );

        let frame = state.ingest_touch(
            Duration::from_millis(1),
            &report(Some([0x31, 0xff, 0x7f, 0x7f])),
        );

        assert_eq!(frame.timestamp, Duration::from_millis(1));
        assert!(frame.fn_pressed);
        assert_eq!(frame.contacts.len(), 1);
        assert!((frame.contacts[0].x - 100.0).abs() < f64::EPSILON);
        assert!((frame.contacts[0].y - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn fn_edge_emits_immediately_with_current_contacts() {
        let mut state = state();
        let _ = state.ingest_touch(Duration::from_millis(1), &report(Some([0x31, 1, 0, 1])));

        let frame = state
            .set_fn_pressed(Duration::from_millis(2), true)
            .expect("state changed");

        assert_eq!(frame.timestamp, Duration::from_millis(2));
        assert!(frame.fn_pressed);
        assert_eq!(frame.contacts.len(), 1);
        assert!(
            state
                .set_fn_pressed(Duration::from_millis(3), true)
                .is_none()
        );
    }

    #[test]
    fn fn_edge_before_touch_emits_an_empty_frame() {
        let frame = state()
            .set_fn_pressed(Duration::from_millis(1), true)
            .expect("state changed");

        assert!(frame.fn_pressed);
        assert!(frame.contacts.is_empty());
    }

    #[test]
    fn idle_after_active_touch_emits_one_empty_frame() {
        let mut state = state();
        let _ = state.set_fn_pressed(Duration::from_millis(1), true);
        let _ = state.ingest_touch(Duration::from_millis(2), &report(Some([0x31, 1, 0, 1])));

        let frame = state
            .touch_idle(Duration::from_millis(3))
            .expect("active contacts were cleared");

        assert!(frame.fn_pressed);
        assert!(frame.contacts.is_empty());
        assert!(state.touch_idle(Duration::from_millis(4)).is_none());
    }

    #[test]
    fn explicit_empty_touch_prevents_duplicate_idle_frame() {
        let mut state = state();
        let _ = state.ingest_touch(Duration::from_millis(1), &report(Some([0x31, 1, 0, 1])));

        let frame = state.ingest_touch(Duration::from_millis(2), &report(None));

        assert!(frame.contacts.is_empty());
        assert!(state.touch_idle(Duration::from_millis(3)).is_none());
    }

    #[test]
    fn touch_can_resume_after_idle_release() {
        let mut state = state();
        let _ = state.ingest_touch(Duration::from_millis(1), &report(Some([0x31, 1, 0, 1])));
        let _ = state.touch_idle(Duration::from_millis(2));

        let frame = state.ingest_touch(Duration::from_millis(3), &report(Some([0x32, 2, 0, 2])));

        assert_eq!(frame.contacts.len(), 1);
        assert_eq!(frame.contacts[0].id, 2);
    }
}
