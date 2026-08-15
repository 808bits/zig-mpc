//! Message envelopes shared by every protocol round.
//!
//! Rounds both consume and produce point-to-point messages, and the two
//! directions carry different party indices: an incoming message is tagged
//! with who sent it, an outgoing one with who it is for. Giving them distinct
//! types means the compiler catches a mix-up that would otherwise surface as
//! a failed proof several rounds later.

/// An incoming message, tagged with its sender's 1-based party index.
pub fn From(comptime T: type) type {
    return struct { from: u16, msg: T };
}

/// An outgoing point-to-point message, tagged with its recipient's 1-based
/// party index.
pub fn To(comptime T: type) type {
    return struct { to: u16, msg: T };
}
