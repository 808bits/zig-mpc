//! What a protocol abort means, in one place.
//!
//! Every round in this library reports failure as a plain Zig error, which
//! carries a name and nothing else: not who caused it, and not whether trying
//! again could possibly work. Each command then re-derived that context from
//! the error name in its own hand-written switch, so the same failure was
//! explained in four files and any round that grew a new error silently fell
//! through to a bare name on the terminal.
//!
//! This module holds the taxonomy those switches were approximating. A
//! [`Reason`] is the protocol-level event, independent of which error value
//! happened to encode it; [`Kind`] is the operator's question, which is not
//! "what broke" but "can I run this again, and with whom". The split follows
//! DKLs23's `AbortReason`/`AbortKind` (eprint 2023/765), which draws the same
//! line for the same reason.
//!
//! # Attribution
//!
//! `ban_counterparty` is deliberately narrow. It means a correct peer running
//! a correct implementation cannot produce this message: a proof that does not
//! verify, an opened commitment that does not match the one published, a share
//! inconsistent with its own commitment. Those are attributable on the
//! transcript alone.
//!
//! Framing failures are not. A truncated or undecodable message is `recoverable`
//! rather than attributable, because without authenticated transport a corrupted
//! wire and a hostile peer are indistinguishable from here. Adding per-message
//! authentication (the frame format already reserves a flag bit for it) is what
//! would let those move.
//!
//! `unattributable` is the honest middle: the round failed a cryptographic
//! check, but the check is over a value every signer contributed to, so no
//! single party falls out of it. CGGMP24's δ check is the live example.
//!
//! # Culprit
//!
//! [`Abort.culprit`] is filled in where the caller already knows who produced
//! the offending value, which today means FROST's per-share verification. The
//! rounds themselves know the index at the point they fail but return it
//! nowhere, because their states are passed by value and have no out-param to
//! carry it. Threading that through is the other half of identifiable abort and
//! is not done here.

const std = @import("std");

/// What the operator should do next.
pub const Kind = enum {
    /// The participant set and the messages did not line up: something is
    /// missing, doubled, or undecodable. Re-running the round after the
    /// transport settles can succeed.
    recoverable,

    /// A cryptographic check over a jointly computed value failed. The round
    /// cannot succeed as-is, but the transcript does not say who caused it.
    unattributable,

    /// A peer produced a value a correct implementation cannot produce.
    /// Re-running with the same set fails the same way; exclude them.
    ban_counterparty,
};

/// The protocol-level event behind an abort, independent of the error value
/// used to signal it.
pub const Reason = enum {
    // --- participant set and message routing ---
    missing_message,
    unexpected_sender,
    duplicate_sender,
    malformed_message,
    invalid_participant_set,

    // --- commitments and shares ---
    decommitment_mismatch,
    wrong_commitment_length,
    inconsistent_share,

    // --- zero-knowledge proofs ---
    invalid_proof,
    invalid_schnorr_proof,
    invalid_enc_proof,
    invalid_aff_g_proof,
    invalid_elog_proof,
    invalid_prm_proof,
    invalid_mod_proof,
    invalid_fac_proof,

    // --- CGGMP24 setup material ---
    invalid_modulus,
    invalid_pedersen_params,

    // --- jointly computed values ---
    delta_mismatch,
    invalid_signature_share,
    aggregate_signature_invalid,

    /// Short label for the header line. Lowercase, no trailing punctuation,
    /// so it reads as a continuation of "<phase> aborted: ".
    pub fn summary(self: Reason) []const u8 {
        return switch (self) {
            .missing_message => "missing message",
            .unexpected_sender => "message from outside the participant set",
            .duplicate_sender => "duplicate message",
            .malformed_message => "undecodable message",
            .invalid_participant_set => "inconsistent participant set",

            .decommitment_mismatch => "decommitment mismatch",
            .wrong_commitment_length => "wrong commitment length",
            .inconsistent_share => "inconsistent secret share",

            .invalid_proof => "invalid proof",
            .invalid_schnorr_proof => "invalid Schnorr proof",
            .invalid_enc_proof => "invalid Πenc range proof",
            .invalid_aff_g_proof => "invalid Πaff-g range proof",
            .invalid_elog_proof => "invalid Πelog proof",
            .invalid_prm_proof => "invalid Πprm proof",
            .invalid_mod_proof => "invalid Πmod proof",
            .invalid_fac_proof => "invalid Πfac proof",

            .invalid_modulus => "unusable Paillier modulus",
            .invalid_pedersen_params => "unusable ring-Pedersen parameters",

            .delta_mismatch => "δ does not match the group element",
            .invalid_signature_share => "invalid signature share",
            .aggregate_signature_invalid => "aggregated signature failed verification",
        };
    }

    /// One sentence saying what actually happened, aimed at whoever is staring
    /// at a failed ceremony.
    pub fn detail(self: Reason) []const u8 {
        return switch (self) {
            .missing_message => "a message from at least one peer has not arrived, or the round " ++
                "ran against the wrong participant set",
            .unexpected_sender => "a message carried a sender index that is not in this session",
            .duplicate_sender => "two messages claimed to come from the same party",
            .malformed_message => "a peer's message could not be decoded; it was corrupted in " ++
                "transit or written by an incompatible version",
            .invalid_participant_set => "the parties, threshold, or commitment list do not agree " ++
                "with the key share this round was given",

            .decommitment_mismatch => "a peer opened a commitment it did not make in round 1",
            .wrong_commitment_length => "a peer published a commitment of the wrong degree for " ++
                "this threshold",
            .inconsistent_share => "a peer sent a secret share inconsistent with the commitment " ++
                "it published",

            .invalid_proof => "a peer's zero-knowledge proof did not verify",
            .invalid_schnorr_proof => "a peer failed to prove knowledge of its secret contribution",
            .invalid_enc_proof => "a signer could not prove its encrypted nonce is in range",
            .invalid_aff_g_proof => "a signer's multiplicative-to-additive step failed its range proof",
            .invalid_elog_proof => "a signer's discrete-log equality proof failed",
            .invalid_prm_proof => "a peer could not prove its ring-Pedersen parameters are well formed",
            .invalid_mod_proof => "a peer's Paillier modulus is not a Blum integer",
            .invalid_fac_proof => "a peer could not prove its modulus has no small factors",

            .invalid_modulus => "a peer offered a Paillier modulus that is undersized, even, or " ++
                "otherwise unusable",
            .invalid_pedersen_params => "a peer's ring-Pedersen parameters are not a valid pair of units",

            .delta_mismatch => "the combined δ does not match the group element: a signer cheated, " ++
                "or the signing set disagrees about the message or the key",
            .invalid_signature_share => "it signed a different message, used a different key share, " ++
                "or is faulty",
            .aggregate_signature_invalid => "every share verified on its own but the combined " ++
                "signature does not; the signing set or the public key is wrong",
        };
    }

    /// Whether this is worth retrying, and with whom.
    pub fn kind(self: Reason) Kind {
        return switch (self) {
            .missing_message,
            .unexpected_sender,
            .duplicate_sender,
            .malformed_message,
            .invalid_participant_set,
            => .recoverable,

            .delta_mismatch,
            .aggregate_signature_invalid,
            => .unattributable,

            .decommitment_mismatch,
            .wrong_commitment_length,
            .inconsistent_share,
            .invalid_proof,
            .invalid_schnorr_proof,
            .invalid_enc_proof,
            .invalid_aff_g_proof,
            .invalid_elog_proof,
            .invalid_prm_proof,
            .invalid_mod_proof,
            .invalid_fac_proof,
            .invalid_modulus,
            .invalid_pedersen_params,
            .invalid_signature_share,
            => .ban_counterparty,
        };
    }
};

/// A reason plus, when the caller can name one, the party that caused it.
pub const Abort = struct {
    reason: Reason,
    /// 1-based party index, when the failure is pinned to a single peer.
    culprit: ?u16 = null,

    pub fn kind(self: Abort) Kind {
        return self.reason.kind();
    }

    pub fn summary(self: Abort) []const u8 {
        return self.reason.summary();
    }

    pub fn detail(self: Abort) []const u8 {
        return self.reason.detail();
    }
};

/// Map an error value onto the protocol event it stands for.
///
/// Returns null when the error is not a protocol event at all: an allocation
/// failure or an I/O error that happened to surface at a round boundary. Those
/// must not be reported as an abort, because nothing about the protocol or the
/// peers went wrong.
pub fn classify(err: anyerror) ?Reason {
    return switch (err) {
        error.MissingMessage,
        error.MissingOwnCommitment,
        error.NoPartialSignatures,
        => .missing_message,

        error.InvalidSender,
        error.InvalidPartyIndex,
        error.InvalidIdentifier,
        error.ParticipantNotInList,
        => .unexpected_sender,

        error.DuplicateMessage,
        error.DuplicateIndex,
        => .duplicate_sender,

        error.Malformed,
        error.MalformedEncoding,
        error.NonCanonical,
        error.InvalidEncoding,
        error.InvalidEnumTag,
        error.TrailingData,
        error.EndOfStream,
        => .malformed_message,

        error.ShareDoesNotMatchState,
        error.ShareCountMismatch,
        error.ThresholdMismatch,
        error.TooManyParticipants,
        error.InvalidThreshold,
        error.InvalidParams,
        error.EmptyCommitment,
        error.EmptyCommitmentList,
        error.UnsortedCommitmentList,
        => .invalid_participant_set,

        error.DecommitmentMismatch,
        error.NonceCommitmentMismatch,
        => .decommitment_mismatch,

        error.InvalidCommitmentLength => .wrong_commitment_length,

        error.InvalidShare,
        error.InconsistentShare,
        => .inconsistent_share,

        error.InvalidProof => .invalid_proof,
        error.InvalidSchnorrProof => .invalid_schnorr_proof,
        error.InvalidEncProof => .invalid_enc_proof,
        error.InvalidAffGProof => .invalid_aff_g_proof,
        error.InvalidElogProof => .invalid_elog_proof,
        error.InvalidPrmProof => .invalid_prm_proof,

        error.InvalidModProof,
        error.NotBlum,
        => .invalid_mod_proof,

        error.InvalidFacProof => .invalid_fac_proof,

        error.InvalidModulus,
        error.InvalidModulusSize,
        error.EvenModulus,
        => .invalid_modulus,

        error.InvalidPedersenParams => .invalid_pedersen_params,

        error.MismatchedDelta => .delta_mismatch,

        else => null,
    };
}

const testing = std.testing;

test "every reason describes itself" {
    for (std.enums.values(Reason)) |r| {
        try testing.expect(r.summary().len > 0);
        try testing.expect(r.detail().len > 0);
        // The summary continues "<phase> aborted: ", so it must not open with
        // a capital or close with a full stop.
        try testing.expect(r.summary()[r.summary().len - 1] != '.');
        _ = r.kind();
    }
}

test "classify covers the errors the rounds actually return" {
    // Every error value reachable from a protocol round must land somewhere.
    // A round that grows a new error and forgets this list gets a bare name on
    // the terminal, which is the failure mode this module exists to remove.
    const covered = [_]anyerror{
        error.MissingMessage,          error.MissingOwnCommitment,   error.NoPartialSignatures,
        error.InvalidSender,           error.InvalidPartyIndex,      error.InvalidIdentifier,
        error.ParticipantNotInList,    error.DuplicateMessage,       error.DuplicateIndex,
        error.Malformed,               error.MalformedEncoding,      error.NonCanonical,
        error.InvalidEncoding,         error.InvalidEnumTag,         error.TrailingData,
        error.EndOfStream,             error.ShareDoesNotMatchState, error.ShareCountMismatch,
        error.ThresholdMismatch,       error.TooManyParticipants,    error.InvalidThreshold,
        error.InvalidParams,           error.EmptyCommitment,        error.EmptyCommitmentList,
        error.UnsortedCommitmentList,  error.DecommitmentMismatch,   error.NonceCommitmentMismatch,
        error.InvalidCommitmentLength, error.InvalidShare,           error.InconsistentShare,
        error.InvalidProof,            error.InvalidSchnorrProof,    error.InvalidEncProof,
        error.InvalidAffGProof,        error.InvalidElogProof,       error.InvalidPrmProof,
        error.InvalidModProof,         error.NotBlum,                error.InvalidFacProof,
        error.InvalidModulus,          error.InvalidModulusSize,     error.EvenModulus,
        error.InvalidPedersenParams,   error.MismatchedDelta,
    };
    for (covered) |e| try testing.expect(classify(e) != null);
}

test "resource failures are not protocol aborts" {
    // Reporting these as an abort would blame the peers for a local problem
    // and exit 65 where the caller needs to see 1.
    try testing.expect(classify(error.OutOfMemory) == null);
    try testing.expect(classify(error.AccessDenied) == null);
    try testing.expect(classify(error.FileNotFound) == null);
}

test "kinds line up with attribution" {
    // A ban is a claim about a specific peer, so it must never be raised for
    // something the transcript cannot pin on one.
    try testing.expectEqual(Kind.ban_counterparty, Reason.invalid_schnorr_proof.kind());
    try testing.expectEqual(Kind.ban_counterparty, Reason.inconsistent_share.kind());
    try testing.expectEqual(Kind.unattributable, Reason.delta_mismatch.kind());
    try testing.expectEqual(Kind.recoverable, Reason.malformed_message.kind());
    try testing.expectEqual(Kind.recoverable, Reason.missing_message.kind());
}
