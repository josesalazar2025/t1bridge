use std::{error::Error, fmt};

const BYTES_PER_PIXEL: u32 = 4;
const MAX_REGISTERED_BUFFERS: usize = 3;
const MAX_DAMAGE_RECTANGLES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameLayout {
    width: u32,
    height: u32,
    stride: u32,
    byte_length: u64,
}

impl FrameLayout {
    /// Derives the only accepted buffer layout from negotiated display dimensions.
    ///
    /// # Errors
    ///
    /// Returns [`FrameStateError::InvalidLayout`] for zero dimensions or if a
    /// required size calculation overflows.
    pub fn new(width: u32, height: u32) -> Result<Self, FrameStateError> {
        if width == 0 || height == 0 {
            return Err(FrameStateError::InvalidLayout);
        }
        let stride = width
            .checked_mul(BYTES_PER_PIXEL)
            .ok_or(FrameStateError::InvalidLayout)?;
        let byte_length = u64::from(stride)
            .checked_mul(u64::from(height))
            .ok_or(FrameStateError::InvalidLayout)?;
        Ok(Self {
            width,
            height,
            stride,
            byte_length,
        })
    }

    #[must_use]
    pub fn width(self) -> u32 {
        self.width
    }

    #[must_use]
    pub fn height(self) -> u32 {
        self.height
    }

    #[must_use]
    pub fn stride(self) -> u32 {
        self.stride
    }

    #[must_use]
    pub fn byte_length(self) -> u64 {
        self.byte_length
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedBufferMetadata {
    pub stride: u32,
    pub byte_length: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DamageRectangle {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedSubmission<BufferId, FrameId> {
    pub buffer_id: BufferId,
    pub frame_id: FrameId,
    pub damage: Vec<DamageRectangle>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameRelease<BufferId, FrameId> {
    pub buffer_id: BufferId,
    pub frame_id: FrameId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameStateError {
    InvalidLayout,
    InvalidBufferStride,
    InvalidBufferLength,
    DuplicateBuffer,
    TooManyBuffers,
    UnknownBuffer,
    BufferInFlight,
    TooManyDamageRectangles,
    DamageOutOfBounds,
    BufferNotInFlight,
    FrameMismatch,
}

impl fmt::Display for FrameStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidLayout => "invalid negotiated frame layout",
            Self::InvalidBufferStride => "buffer stride does not match the negotiated layout",
            Self::InvalidBufferLength => "buffer length does not match the negotiated layout",
            Self::DuplicateBuffer => "buffer is already registered",
            Self::TooManyBuffers => "registered buffer limit reached",
            Self::UnknownBuffer => "buffer is not registered",
            Self::BufferInFlight => "buffer is still in flight",
            Self::TooManyDamageRectangles => "damage rectangle limit exceeded",
            Self::DamageOutOfBounds => "damage rectangle is outside the negotiated display",
            Self::BufferNotInFlight => "buffer has no frame in flight",
            Self::FrameMismatch => "release does not match the frame in flight",
        };
        formatter.write_str(message)
    }
}

impl Error for FrameStateError {}

#[derive(Debug)]
struct RegisteredBuffer<BufferId, FrameId> {
    id: BufferId,
    in_flight: Option<FrameId>,
}

#[derive(Debug)]
pub struct FrameState<BufferId, FrameId> {
    layout: FrameLayout,
    buffers: Vec<RegisteredBuffer<BufferId, FrameId>>,
}

impl<BufferId, FrameId> FrameState<BufferId, FrameId>
where
    BufferId: Clone + Eq,
    FrameId: Clone + Eq,
{
    #[must_use]
    pub fn new(layout: FrameLayout) -> Self {
        Self {
            layout,
            buffers: Vec::with_capacity(MAX_REGISTERED_BUFFERS),
        }
    }

    /// Registers a buffer whose file type, seals, size, and mapping safety were
    /// already verified by the caller.
    ///
    /// # Errors
    ///
    /// Returns [`FrameStateError`] if the semantic metadata does not match the
    /// negotiated layout, the identifier is already present, or the registry
    /// is full.
    pub fn register_buffer(
        &mut self,
        buffer_id: BufferId,
        metadata: VerifiedBufferMetadata,
    ) -> Result<(), FrameStateError> {
        if metadata.stride != self.layout.stride {
            return Err(FrameStateError::InvalidBufferStride);
        }
        if metadata.byte_length != self.layout.byte_length {
            return Err(FrameStateError::InvalidBufferLength);
        }
        if self.buffers.iter().any(|buffer| buffer.id == buffer_id) {
            return Err(FrameStateError::DuplicateBuffer);
        }
        if self.buffers.len() == MAX_REGISTERED_BUFFERS {
            return Err(FrameStateError::TooManyBuffers);
        }
        self.buffers.push(RegisteredBuffer {
            id: buffer_id,
            in_flight: None,
        });
        Ok(())
    }

    /// Validates and takes ownership of a submitted buffer until exact release.
    ///
    /// An empty damage list becomes one whole-display rectangle.
    ///
    /// # Errors
    ///
    /// Returns [`FrameStateError`] for an unknown or in-flight buffer, excessive
    /// damage count, or a rectangle outside the negotiated display.
    pub fn submit_frame(
        &mut self,
        buffer_id: &BufferId,
        frame_id: FrameId,
        damage: &[DamageRectangle],
    ) -> Result<ValidatedSubmission<BufferId, FrameId>, FrameStateError> {
        let buffer_index = self
            .buffers
            .iter()
            .position(|buffer| &buffer.id == buffer_id)
            .ok_or(FrameStateError::UnknownBuffer)?;
        if self.buffers[buffer_index].in_flight.is_some() {
            return Err(FrameStateError::BufferInFlight);
        }

        let normalized_damage = self.validate_damage(damage)?;
        let buffer = &mut self.buffers[buffer_index];
        buffer.in_flight = Some(frame_id.clone());
        Ok(ValidatedSubmission {
            buffer_id: buffer.id.clone(),
            frame_id,
            damage: normalized_damage,
        })
    }

    /// Releases only the exact buffer/frame pair currently in flight.
    ///
    /// Presented, dropped, and superseded frames all use this explicit
    /// transition; no other operation makes a submitted buffer writable again.
    ///
    /// # Errors
    ///
    /// Returns [`FrameStateError`] if the buffer is unknown, available already,
    /// or owned by a different frame.
    pub fn release_frame(
        &mut self,
        buffer_id: &BufferId,
        frame_id: &FrameId,
    ) -> Result<FrameRelease<BufferId, FrameId>, FrameStateError> {
        let buffer = self
            .buffers
            .iter_mut()
            .find(|buffer| &buffer.id == buffer_id)
            .ok_or(FrameStateError::UnknownBuffer)?;
        let Some(in_flight) = buffer.in_flight.as_ref() else {
            return Err(FrameStateError::BufferNotInFlight);
        };
        if in_flight != frame_id {
            return Err(FrameStateError::FrameMismatch);
        }

        buffer.in_flight = None;
        Ok(FrameRelease {
            buffer_id: buffer.id.clone(),
            frame_id: frame_id.clone(),
        })
    }

    pub fn disconnect(&mut self) {
        self.buffers.clear();
    }

    #[must_use]
    pub fn registered_buffer_count(&self) -> usize {
        self.buffers.len()
    }

    #[must_use]
    pub fn in_flight_count(&self) -> usize {
        self.buffers
            .iter()
            .filter(|buffer| buffer.in_flight.is_some())
            .count()
    }

    fn validate_damage(
        &self,
        damage: &[DamageRectangle],
    ) -> Result<Vec<DamageRectangle>, FrameStateError> {
        if damage.len() > MAX_DAMAGE_RECTANGLES {
            return Err(FrameStateError::TooManyDamageRectangles);
        }
        if damage.is_empty() {
            return Ok(vec![DamageRectangle {
                x: 0,
                y: 0,
                width: self.layout.width,
                height: self.layout.height,
            }]);
        }
        if damage.iter().any(|rectangle| {
            rectangle
                .x
                .checked_add(rectangle.width)
                .is_none_or(|right| right > self.layout.width)
                || rectangle
                    .y
                    .checked_add(rectangle.height)
                    .is_none_or(|bottom| bottom > self.layout.height)
        }) {
            return Err(FrameStateError::DamageOutOfBounds);
        }
        Ok(damage.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIDTH: u32 = 100;
    const HEIGHT: u32 = 20;

    fn layout() -> FrameLayout {
        FrameLayout::new(WIDTH, HEIGHT).expect("valid layout")
    }

    fn metadata() -> VerifiedBufferMetadata {
        VerifiedBufferMetadata {
            stride: WIDTH * BYTES_PER_PIXEL,
            byte_length: u64::from(WIDTH * BYTES_PER_PIXEL * HEIGHT),
        }
    }

    fn state() -> FrameState<&'static str, u64> {
        FrameState::new(layout())
    }

    #[test]
    fn derives_checked_layout_sizes() {
        let layout = layout();
        assert_eq!(layout.width(), WIDTH);
        assert_eq!(layout.height(), HEIGHT);
        assert_eq!(layout.stride(), 400);
        assert_eq!(layout.byte_length(), 8_000);
        assert_eq!(
            FrameLayout::new(0, HEIGHT),
            Err(FrameStateError::InvalidLayout)
        );
        assert_eq!(
            FrameLayout::new(u32::MAX, HEIGHT),
            Err(FrameStateError::InvalidLayout)
        );
    }

    #[test]
    fn registration_requires_exact_stride_and_length() {
        let mut state = state();
        assert_eq!(
            state.register_buffer(
                "bad-stride",
                VerifiedBufferMetadata {
                    stride: metadata().stride - 1,
                    ..metadata()
                }
            ),
            Err(FrameStateError::InvalidBufferStride)
        );
        assert_eq!(
            state.register_buffer(
                "bad-length",
                VerifiedBufferMetadata {
                    byte_length: metadata().byte_length - 1,
                    ..metadata()
                }
            ),
            Err(FrameStateError::InvalidBufferLength)
        );
        assert_eq!(state.registered_buffer_count(), 0);
    }

    #[test]
    fn registration_is_unique_and_bounded_to_three() {
        let mut state = state();
        state.register_buffer("one", metadata()).expect("slot one");
        assert_eq!(
            state.register_buffer("one", metadata()),
            Err(FrameStateError::DuplicateBuffer)
        );
        state.register_buffer("two", metadata()).expect("slot two");
        state
            .register_buffer("three", metadata())
            .expect("slot three");
        assert_eq!(
            state.register_buffer("four", metadata()),
            Err(FrameStateError::TooManyBuffers)
        );
        assert_eq!(state.registered_buffer_count(), 3);
    }

    #[test]
    fn empty_damage_normalizes_to_the_whole_frame() {
        let mut state = state();
        state.register_buffer("buffer", metadata()).expect("buffer");

        let submission = state
            .submit_frame(&"buffer", 7, &[])
            .expect("valid submission");

        assert_eq!(
            submission.damage,
            vec![DamageRectangle {
                x: 0,
                y: 0,
                width: WIDTH,
                height: HEIGHT,
            }]
        );
    }

    #[test]
    fn accepts_at_most_sixty_four_in_bounds_rectangles() {
        let mut state = state();
        state.register_buffer("buffer", metadata()).expect("buffer");
        let damage = vec![
            DamageRectangle {
                x: WIDTH - 1,
                y: HEIGHT - 1,
                width: 1,
                height: 1,
            };
            MAX_DAMAGE_RECTANGLES
        ];

        let submission = state
            .submit_frame(&"buffer", 1, &damage)
            .expect("bounded damage");

        assert_eq!(submission.damage, damage);
    }

    #[test]
    fn rejects_excessive_or_out_of_bounds_damage_without_taking_buffer() {
        let mut state = state();
        state.register_buffer("buffer", metadata()).expect("buffer");
        let too_many = vec![
            DamageRectangle {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
            };
            MAX_DAMAGE_RECTANGLES + 1
        ];
        assert_eq!(
            state.submit_frame(&"buffer", 1, &too_many),
            Err(FrameStateError::TooManyDamageRectangles)
        );
        assert_eq!(
            state.submit_frame(
                &"buffer",
                2,
                &[DamageRectangle {
                    x: WIDTH,
                    y: 0,
                    width: 1,
                    height: 1,
                }]
            ),
            Err(FrameStateError::DamageOutOfBounds)
        );
        assert_eq!(
            state.submit_frame(
                &"buffer",
                3,
                &[DamageRectangle {
                    x: 0,
                    y: HEIGHT,
                    width: 1,
                    height: 1,
                }]
            ),
            Err(FrameStateError::DamageOutOfBounds)
        );
        assert_eq!(state.in_flight_count(), 0);
    }

    #[test]
    fn rejects_coordinate_addition_overflow() {
        let mut state = state();
        state.register_buffer("buffer", metadata()).expect("buffer");
        assert_eq!(
            state.submit_frame(
                &"buffer",
                1,
                &[DamageRectangle {
                    x: u32::MAX,
                    y: 0,
                    width: 2,
                    height: 1,
                }]
            ),
            Err(FrameStateError::DamageOutOfBounds)
        );
    }

    #[test]
    fn submitted_buffer_requires_exact_explicit_release() {
        let mut state = state();
        state.register_buffer("buffer", metadata()).expect("buffer");
        state.submit_frame(&"buffer", 7, &[]).expect("submit");

        assert_eq!(
            state.submit_frame(&"buffer", 8, &[]),
            Err(FrameStateError::BufferInFlight)
        );
        assert_eq!(
            state.release_frame(&"buffer", &8),
            Err(FrameStateError::FrameMismatch)
        );
        assert_eq!(state.in_flight_count(), 1);

        assert_eq!(
            state.release_frame(&"buffer", &7).expect("exact release"),
            FrameRelease {
                buffer_id: "buffer",
                frame_id: 7,
            }
        );
        assert_eq!(state.in_flight_count(), 0);
        state
            .submit_frame(&"buffer", 8, &[])
            .expect("reusable after release");
    }

    #[test]
    fn dropped_or_superseded_work_does_not_implicitly_release() {
        let mut state = state();
        state
            .register_buffer("old", metadata())
            .expect("old buffer");
        state
            .register_buffer("new", metadata())
            .expect("new buffer");
        state.submit_frame(&"old", 1, &[]).expect("old frame");
        state.submit_frame(&"new", 2, &[]).expect("new frame");

        assert_eq!(state.in_flight_count(), 2);
        assert_eq!(
            state.submit_frame(&"old", 3, &[]),
            Err(FrameStateError::BufferInFlight)
        );
        state
            .release_frame(&"old", &1)
            .expect("explicit superseded release");
        state
            .release_frame(&"new", &2)
            .expect("explicit dropped release");
        assert_eq!(state.in_flight_count(), 0);
    }

    #[test]
    fn release_rejects_unknown_and_available_buffers() {
        let mut state = state();
        state.register_buffer("buffer", metadata()).expect("buffer");
        assert_eq!(
            state.release_frame(&"missing", &1),
            Err(FrameStateError::UnknownBuffer)
        );
        assert_eq!(
            state.release_frame(&"buffer", &1),
            Err(FrameStateError::BufferNotInFlight)
        );
    }

    #[test]
    fn disconnect_clears_registered_and_in_flight_state() {
        let mut state = state();
        state.register_buffer("buffer", metadata()).expect("buffer");
        state.submit_frame(&"buffer", 1, &[]).expect("submit");

        state.disconnect();

        assert_eq!(state.registered_buffer_count(), 0);
        assert_eq!(state.in_flight_count(), 0);
        assert_eq!(
            state.release_frame(&"buffer", &1),
            Err(FrameStateError::UnknownBuffer)
        );
        state
            .register_buffer("buffer", metadata())
            .expect("clean registry is reusable");
    }

    #[test]
    fn diagnostics_do_not_include_caller_identifiers_or_values() {
        let mut state: FrameState<String, String> = FrameState::new(layout());
        let private_id = "caller-private-buffer-value".to_owned();
        let error = state
            .submit_frame(&private_id, "caller-private-frame-value".to_owned(), &[])
            .expect_err("buffer is unknown");

        assert_eq!(error.to_string(), "buffer is not registered");
        assert!(!error.to_string().contains("private"));
    }
}
