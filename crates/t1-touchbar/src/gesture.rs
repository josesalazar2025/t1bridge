//! Deterministic gesture recognition over validated display contacts.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::time::Duration;

/// Stable identifier for one contact while it remains on the display.
pub type ContactId = u32;

/// One active contact in display-pixel coordinates.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DisplayContact {
    id: ContactId,
    x: f64,
    y: f64,
}

impl DisplayContact {
    /// Creates an active display contact.
    ///
    /// # Errors
    ///
    /// Returns [`GestureError::InvalidContactCoordinate`] if either coordinate
    /// is negative or non-finite. Panel-bound validation belongs to the input
    /// boundary that creates these typed contacts.
    pub fn new(id: ContactId, x: f64, y: f64) -> Result<Self, GestureError> {
        if !x.is_finite() || !y.is_finite() || x < 0.0 || y < 0.0 {
            return Err(GestureError::InvalidContactCoordinate);
        }
        Ok(Self { id, x, y })
    }

    /// Returns the contact identifier.
    #[must_use]
    pub const fn id(self) -> ContactId {
        self.id
    }

    /// Returns the horizontal display coordinate.
    #[must_use]
    pub const fn x(self) -> f64 {
        self.x
    }

    /// Returns the vertical display coordinate.
    #[must_use]
    pub const fn y(self) -> f64 {
        self.y
    }
}

/// Caller-selected gesture thresholds and capacity.
///
/// This type deliberately has no default: product configuration must choose
/// every gesture threshold and timing value explicitly.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GestureSettings {
    drag_distance: f64,
    hold_after: Duration,
    max_contacts: usize,
}

impl GestureSettings {
    /// Validates caller-selected gesture settings.
    ///
    /// A zero drag distance makes the first update a drag, and a zero hold
    /// duration emits a hold in the same frame as a press.
    ///
    /// # Errors
    ///
    /// Returns an error when the drag distance is negative or non-finite, or
    /// when the contact capacity is zero.
    pub fn new(
        drag_distance: f64,
        hold_after: Duration,
        max_contacts: usize,
    ) -> Result<Self, GestureError> {
        if !drag_distance.is_finite() || drag_distance < 0.0 {
            return Err(GestureError::InvalidDragDistance);
        }
        if max_contacts == 0 {
            return Err(GestureError::InvalidContactCapacity);
        }
        Ok(Self {
            drag_distance,
            hold_after,
            max_contacts,
        })
    }

    /// Returns the distance from the initial press that begins a drag.
    #[must_use]
    pub const fn drag_distance(self) -> f64 {
        self.drag_distance
    }

    /// Returns the stationary interval that emits a hold.
    #[must_use]
    pub const fn hold_after(self) -> Duration {
        self.hold_after
    }

    /// Returns the maximum number of simultaneous contacts.
    #[must_use]
    pub const fn max_contacts(self) -> usize {
        self.max_contacts
    }
}

/// One state transition emitted by the gesture engine.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Gesture {
    /// A previously absent contact appeared.
    Press(DisplayContact),
    /// A contact moved without crossing the drag threshold.
    Move {
        /// Position before this input frame.
        from: DisplayContact,
        /// Position in this input frame.
        to: DisplayContact,
    },
    /// A contact first crossed the drag threshold, at its press position.
    DragStart(DisplayContact),
    /// A dragging contact moved.
    Drag {
        /// Position before this input frame.
        from: DisplayContact,
        /// Position in this input frame.
        to: DisplayContact,
    },
    /// A stationary contact reached the hold interval.
    Hold(DisplayContact),
    /// A contact disappeared or all contacts were explicitly released.
    Release(DisplayContact),
    /// A released contact had neither dragged nor held.
    Tap(DisplayContact),
}

/// A rejected settings value or input-frame transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GestureError {
    /// The caller supplied a negative or non-finite drag distance.
    InvalidDragDistance,
    /// The caller supplied a zero contact capacity.
    InvalidContactCapacity,
    /// A display coordinate was negative or non-finite.
    InvalidContactCoordinate,
    /// An input frame exceeded the caller-selected contact capacity.
    TooManyContacts,
    /// An input frame repeated a contact identifier.
    DuplicateContact,
    /// An input timestamp preceded a previously accepted timestamp.
    TimestampRegressed,
}

impl fmt::Display for GestureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidDragDistance => "invalid gesture drag distance",
            Self::InvalidContactCapacity => "invalid gesture contact capacity",
            Self::InvalidContactCoordinate => "invalid gesture contact coordinate",
            Self::TooManyContacts => "gesture input exceeds the contact capacity",
            Self::DuplicateContact => "gesture input repeats a contact",
            Self::TimestampRegressed => "gesture input timestamp regressed",
        })
    }
}

impl Error for GestureError {}

#[derive(Clone, Copy)]
struct ActiveContact {
    start: DisplayContact,
    current: DisplayContact,
    started_at: Duration,
    dragging: bool,
    held: bool,
}

/// Pure, deterministic gesture state for one stream of contact frames.
///
/// Events for simultaneous contacts are always ordered by contact identifier.
/// A rejected frame leaves the complete engine state unchanged.
pub struct GestureEngine {
    settings: GestureSettings,
    active: BTreeMap<ContactId, ActiveContact>,
    last_timestamp: Option<Duration>,
}

impl GestureEngine {
    /// Creates an empty engine using explicit caller-selected settings.
    #[must_use]
    pub const fn new(settings: GestureSettings) -> Self {
        Self {
            settings,
            active: BTreeMap::new(),
            last_timestamp: None,
        }
    }

    /// Reports whether no contact is currently active.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.active.is_empty()
    }

    /// Applies one complete frame of currently active contacts.
    ///
    /// Missing contact identifiers are released before present contacts are
    /// updated or pressed. Hold transitions are evaluated after the frame's
    /// movement transitions at the same timestamp.
    ///
    /// # Errors
    ///
    /// Rejects over-capacity frames, duplicate identifiers, or a timestamp
    /// older than the last accepted operation. Rejection never partially
    /// changes active gesture state.
    pub fn ingest_frame(
        &mut self,
        timestamp: Duration,
        contacts: &[DisplayContact],
    ) -> Result<Vec<Gesture>, GestureError> {
        let ordered = self.validate_frame(contacts)?;
        self.accept_timestamp(timestamp)?;

        let disappeared: Vec<_> = self
            .active
            .keys()
            .copied()
            .filter(|id| !ordered.contains_key(id))
            .collect();
        let mut gestures = Vec::new();
        for id in disappeared {
            self.release(id, &mut gestures);
        }
        for contact in ordered.into_values() {
            self.update_or_press(timestamp, contact, &mut gestures);
        }
        self.emit_holds(timestamp, &mut gestures);
        Ok(gestures)
    }

    /// Advances hold recognition without changing contact positions.
    ///
    /// # Errors
    ///
    /// Returns [`GestureError::TimestampRegressed`] without changing state if
    /// `timestamp` is older than the last accepted operation.
    pub fn tick(&mut self, timestamp: Duration) -> Result<Vec<Gesture>, GestureError> {
        self.accept_timestamp(timestamp)?;
        let mut gestures = Vec::new();
        self.emit_holds(timestamp, &mut gestures);
        Ok(gestures)
    }

    /// Releases every active contact in identifier order.
    ///
    /// This is the explicit transition for an input source that stops sending
    /// reports after the final lift.
    ///
    /// # Errors
    ///
    /// Returns [`GestureError::TimestampRegressed`] without changing state if
    /// `timestamp` is older than the last accepted operation.
    pub fn release_all(&mut self, timestamp: Duration) -> Result<Vec<Gesture>, GestureError> {
        self.accept_timestamp(timestamp)?;
        let ids: Vec<_> = self.active.keys().copied().collect();
        let mut gestures = Vec::new();
        for id in ids {
            self.release(id, &mut gestures);
        }
        Ok(gestures)
    }

    /// Returns the number of currently active contacts.
    #[must_use]
    pub fn contact_count(&self) -> usize {
        self.active.len()
    }

    /// Reports whether no contacts are currently active.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.active.is_empty()
    }

    fn validate_frame(
        &self,
        contacts: &[DisplayContact],
    ) -> Result<BTreeMap<ContactId, DisplayContact>, GestureError> {
        if contacts.len() > self.settings.max_contacts {
            return Err(GestureError::TooManyContacts);
        }
        let mut ordered = BTreeMap::new();
        for contact in contacts.iter().copied() {
            if ordered.insert(contact.id, contact).is_some() {
                return Err(GestureError::DuplicateContact);
            }
        }
        Ok(ordered)
    }

    fn accept_timestamp(&mut self, timestamp: Duration) -> Result<(), GestureError> {
        if self
            .last_timestamp
            .is_some_and(|previous| timestamp < previous)
        {
            return Err(GestureError::TimestampRegressed);
        }
        self.last_timestamp = Some(timestamp);
        Ok(())
    }

    fn update_or_press(
        &mut self,
        timestamp: Duration,
        contact: DisplayContact,
        gestures: &mut Vec<Gesture>,
    ) {
        let Some(active) = self.active.get_mut(&contact.id) else {
            self.active.insert(
                contact.id,
                ActiveContact {
                    start: contact,
                    current: contact,
                    started_at: timestamp,
                    dragging: false,
                    held: false,
                },
            );
            gestures.push(Gesture::Press(contact));
            return;
        };

        let previous = active.current;
        active.current = contact;
        let dx = contact.x - active.start.x;
        let dy = contact.y - active.start.y;
        let distance = dx.hypot(dy);
        if !active.dragging && distance >= self.settings.drag_distance {
            active.dragging = true;
            gestures.push(Gesture::DragStart(active.start));
            gestures.push(Gesture::Drag {
                from: previous,
                to: contact,
            });
        } else if active.dragging {
            gestures.push(Gesture::Drag {
                from: previous,
                to: contact,
            });
        } else {
            gestures.push(Gesture::Move {
                from: previous,
                to: contact,
            });
        }
    }

    fn emit_holds(&mut self, timestamp: Duration, gestures: &mut Vec<Gesture>) {
        for active in self.active.values_mut() {
            if !active.held
                && !active.dragging
                && timestamp.saturating_sub(active.started_at) >= self.settings.hold_after
            {
                active.held = true;
                gestures.push(Gesture::Hold(active.current));
            }
        }
    }

    fn release(&mut self, id: ContactId, gestures: &mut Vec<Gesture>) {
        let Some(active) = self.active.remove(&id) else {
            return;
        };
        gestures.push(Gesture::Release(active.current));
        if !active.dragging && !active.held {
            gestures.push(Gesture::Tap(active.current));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(drag_distance: f64, hold_millis: u64, max_contacts: usize) -> GestureSettings {
        GestureSettings::new(
            drag_distance,
            Duration::from_millis(hold_millis),
            max_contacts,
        )
        .expect("valid synthetic settings")
    }

    fn contact(id: ContactId, x: f64, y: f64) -> DisplayContact {
        DisplayContact::new(id, x, y).expect("valid synthetic contact")
    }

    #[test]
    fn settings_and_contacts_require_explicit_valid_values() {
        assert_eq!(
            GestureSettings::new(f64::NAN, Duration::ZERO, 1),
            Err(GestureError::InvalidDragDistance)
        );
        assert_eq!(
            GestureSettings::new(-1.0, Duration::ZERO, 1),
            Err(GestureError::InvalidDragDistance)
        );
        assert_eq!(
            GestureSettings::new(1.0, Duration::ZERO, 0),
            Err(GestureError::InvalidContactCapacity)
        );
        for (x, y) in [(-1.0, 0.0), (0.0, -1.0), (f64::INFINITY, 0.0)] {
            assert_eq!(
                DisplayContact::new(1, x, y),
                Err(GestureError::InvalidContactCoordinate)
            );
        }
    }

    #[test]
    fn tap_is_press_then_release_and_tap_at_the_latest_position() {
        let mut engine = GestureEngine::new(settings(20.0, 500, 2));
        let start = contact(7, 10.0, 10.0);
        let current = contact(7, 12.0, 13.0);

        assert_eq!(
            engine.ingest_frame(Duration::ZERO, &[start]).unwrap(),
            vec![Gesture::Press(start)]
        );
        assert_eq!(
            engine
                .ingest_frame(Duration::from_millis(10), &[current])
                .unwrap(),
            vec![Gesture::Move {
                from: start,
                to: current
            }]
        );
        assert_eq!(
            engine.ingest_frame(Duration::from_millis(20), &[]).unwrap(),
            vec![Gesture::Release(current), Gesture::Tap(current)]
        );
        assert!(engine.is_empty());
    }

    #[test]
    fn hold_fires_at_the_exact_boundary_once_and_suppresses_tap() {
        let mut engine = GestureEngine::new(settings(10.0, 450, 1));
        let start = contact(1, 5.0, 5.0);
        let _ = engine.ingest_frame(Duration::ZERO, &[start]).unwrap();

        assert!(engine.tick(Duration::from_millis(449)).unwrap().is_empty());
        assert_eq!(
            engine.tick(Duration::from_millis(450)).unwrap(),
            vec![Gesture::Hold(start)]
        );
        assert!(engine.tick(Duration::from_secs(1)).unwrap().is_empty());
        assert_eq!(
            engine.release_all(Duration::from_secs(1)).unwrap(),
            vec![Gesture::Release(start)]
        );
    }

    #[test]
    fn drag_crossing_uses_euclidean_distance_and_suppresses_hold_and_tap() {
        let mut engine = GestureEngine::new(settings(5.0, 100, 1));
        let start = contact(4, 10.0, 10.0);
        let below = contact(4, 12.0, 12.0);
        let boundary = contact(4, 13.0, 14.0);
        let later = contact(4, 20.0, 14.0);
        let _ = engine.ingest_frame(Duration::ZERO, &[start]).unwrap();

        assert_eq!(
            engine
                .ingest_frame(Duration::from_millis(10), &[below])
                .unwrap(),
            vec![Gesture::Move {
                from: start,
                to: below
            }]
        );
        assert_eq!(
            engine
                .ingest_frame(Duration::from_millis(20), &[boundary])
                .unwrap(),
            vec![
                Gesture::DragStart(start),
                Gesture::Drag {
                    from: below,
                    to: boundary
                }
            ]
        );
        assert_eq!(
            engine
                .ingest_frame(Duration::from_millis(150), &[later])
                .unwrap(),
            vec![Gesture::Drag {
                from: boundary,
                to: later
            }]
        );
        assert_eq!(
            engine.release_all(Duration::from_millis(160)).unwrap(),
            vec![Gesture::Release(later)]
        );
    }

    #[test]
    fn multi_contact_events_are_ordered_by_identifier() {
        let mut engine = GestureEngine::new(settings(50.0, 1_000, 3));
        let one = contact(1, 10.0, 1.0);
        let two = contact(2, 20.0, 1.0);
        let two_next = contact(2, 21.0, 1.0);
        let three = contact(3, 30.0, 1.0);

        assert_eq!(
            engine.ingest_frame(Duration::ZERO, &[two, one]).unwrap(),
            vec![Gesture::Press(one), Gesture::Press(two)]
        );
        assert_eq!(
            engine
                .ingest_frame(Duration::from_millis(1), &[three, two_next])
                .unwrap(),
            vec![
                Gesture::Release(one),
                Gesture::Tap(one),
                Gesture::Move {
                    from: two,
                    to: two_next
                },
                Gesture::Press(three)
            ]
        );
        assert_eq!(engine.contact_count(), 2);
    }

    #[test]
    fn disappeared_slots_release_independently() {
        let mut engine = GestureEngine::new(settings(10.0, 50, 2));
        let one = contact(1, 10.0, 1.0);
        let two = contact(2, 20.0, 1.0);
        let _ = engine.ingest_frame(Duration::ZERO, &[one, two]).unwrap();
        let _ = engine.tick(Duration::from_millis(50)).unwrap();

        assert_eq!(
            engine
                .ingest_frame(Duration::from_millis(60), &[two])
                .unwrap(),
            vec![Gesture::Release(one), Gesture::Move { from: two, to: two }]
        );
        assert_eq!(engine.contact_count(), 1);
    }

    #[test]
    fn release_all_is_sorted_and_idempotent() {
        let mut engine = GestureEngine::new(settings(10.0, 500, 3));
        let one = contact(1, 10.0, 1.0);
        let two = contact(2, 20.0, 1.0);
        let _ = engine.ingest_frame(Duration::ZERO, &[two, one]).unwrap();

        assert_eq!(
            engine.release_all(Duration::from_millis(1)).unwrap(),
            vec![
                Gesture::Release(one),
                Gesture::Tap(one),
                Gesture::Release(two),
                Gesture::Tap(two)
            ]
        );
        assert!(
            engine
                .release_all(Duration::from_millis(2))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn invalid_frames_and_time_leave_state_unchanged() {
        let mut engine = GestureEngine::new(settings(10.0, 500, 2));
        let one = contact(1, 10.0, 1.0);
        let two = contact(2, 20.0, 1.0);
        let three = contact(3, 30.0, 1.0);
        let _ = engine
            .ingest_frame(Duration::from_millis(10), &[one])
            .unwrap();

        assert_eq!(
            engine.ingest_frame(Duration::from_millis(11), &[two, two]),
            Err(GestureError::DuplicateContact)
        );
        assert_eq!(
            engine.ingest_frame(Duration::from_millis(11), &[one, two, three]),
            Err(GestureError::TooManyContacts)
        );
        assert_eq!(
            engine.tick(Duration::from_millis(9)),
            Err(GestureError::TimestampRegressed)
        );
        assert_eq!(
            engine.release_all(Duration::from_millis(9)),
            Err(GestureError::TimestampRegressed)
        );
        assert_eq!(engine.contact_count(), 1);
        assert_eq!(
            engine.release_all(Duration::from_millis(12)).unwrap(),
            vec![Gesture::Release(one), Gesture::Tap(one)]
        );
    }

    #[test]
    fn zero_thresholds_have_explicit_boundary_behavior() {
        let mut engine = GestureEngine::new(settings(0.0, 0, 1));
        let point = contact(1, 1.0, 1.0);

        assert_eq!(
            engine.ingest_frame(Duration::ZERO, &[point]).unwrap(),
            vec![Gesture::Press(point), Gesture::Hold(point)]
        );
        assert_eq!(
            engine.ingest_frame(Duration::ZERO, &[point]).unwrap(),
            vec![
                Gesture::DragStart(point),
                Gesture::Drag {
                    from: point,
                    to: point
                }
            ]
        );
        assert_eq!(
            engine.release_all(Duration::ZERO).unwrap(),
            vec![Gesture::Release(point)]
        );
    }
}
