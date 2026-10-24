/// Errors produced while parsing, decoding, or encoding DNS wire data.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtoError {
    /// A label is longer than 63 octets.
    #[error("label of {len} octets exceeds the 63 octet limit")]
    LabelTooLong {
        /// Offending label length.
        len: usize,
    },
    /// A name is longer than 255 octets on the wire.
    #[error("name of {len} wire octets exceeds the 255 octet limit")]
    NameTooLong {
        /// Offending wire length (at least the limit plus one).
        len: usize,
    },
    /// A presentation-format name contains an empty label or is empty.
    #[error("empty label in domain name")]
    EmptyLabel,
    /// A presentation-format escape sequence is malformed.
    #[error("invalid escape sequence in domain name")]
    InvalidEscape,
    /// The message ended in the middle of a name.
    #[error("message truncated at offset {offset}")]
    Truncated {
        /// Offset at which more data was expected.
        offset: usize,
    },
    /// The starting offset lies beyond the end of the message.
    #[error("offset {offset} is beyond the message length {len}")]
    OffsetOutOfBounds {
        /// Requested offset.
        offset: usize,
        /// Message length.
        len: usize,
    },
    /// A label type other than plain or pointer (0x40 or 0x80 prefix) was used.
    #[error("reserved label type {byte:#04x} at offset {offset}")]
    ReservedLabelType {
        /// The offending length/type octet.
        byte: u8,
        /// Offset of that octet.
        offset: usize,
    },
    /// A compression pointer refers to its own position.
    #[error("compression pointer at offset {offset} points to itself")]
    PointerLoop {
        /// Offset of the pointer.
        offset: usize,
    },
    /// A compression pointer does not point strictly backwards.
    #[error("compression pointer at offset {offset} points forward to {target}")]
    ForwardPointer {
        /// Offset of the pointer.
        offset: usize,
        /// Offset it refers to.
        target: usize,
    },
    /// More than 128 compression pointers were followed in one name.
    #[error("too many compression pointer jumps")]
    TooManyPointers,
    /// RDATA does not occupy exactly the number of octets given by RDLENGTH.
    #[error("rdata of type {rtype} does not match its RDLENGTH of {rdlength}")]
    RdataLengthMismatch {
        /// Numeric record type.
        rtype: u16,
        /// The RDLENGTH announced in the record header.
        rdlength: usize,
    },
    /// RDATA (or a value being encoded) violates the rules of its type.
    #[error("invalid rdata for type {rtype}: {reason}")]
    InvalidRdata {
        /// Numeric record type.
        rtype: u16,
        /// Short static description of the violated rule.
        reason: &'static str,
    },
    /// SVCB/HTTPS parameter keys are not in strictly increasing order.
    #[error("svcb parameter key {key} follows {previous}; keys must strictly increase")]
    SvcbKeyOrder {
        /// The previous key.
        previous: u16,
        /// The offending key.
        key: u16,
    },
    /// Section counts announce more records than the remaining data can hold.
    #[error("section counts need at least {needed} octets but only {available} remain")]
    CountsExceedData {
        /// Minimum number of octets the announced entries would occupy.
        needed: usize,
        /// Octets available after the header.
        available: usize,
    },
    /// More than one OPT pseudo-record in the additional section.
    #[error("duplicate OPT record")]
    DuplicateOpt,
    /// An OPT pseudo-record outside the additional section.
    #[error("OPT record in the {section} section")]
    MisplacedOpt {
        /// Name of the section (`answer` or `authority`).
        section: &'static str,
    },
    /// The owner name of an OPT pseudo-record is not the root.
    #[error("OPT record owner name is not the root")]
    OptOwnerNotRoot,
    /// Octets remain after the last announced record.
    #[error("{len} trailing octets after the message at offset {offset}")]
    TrailingData {
        /// Offset of the first unread octet.
        offset: usize,
        /// Number of unread octets.
        len: usize,
    },
    /// An EDNS option or OPT record violates its rules.
    #[error("invalid EDNS data: {reason}")]
    InvalidEdns {
        /// Short static description of the violated rule.
        reason: &'static str,
    },
    /// A message value violates the wire format limits.
    #[error("invalid message: {reason}")]
    InvalidMessage {
        /// Short static description of the violated rule.
        reason: &'static str,
    },
    /// The size limit cannot hold even the header, question and OPT record.
    #[error("limit of {limit} octets is below the {needed} octet minimum message")]
    LimitTooSmall {
        /// Requested limit.
        limit: usize,
        /// Size of the header, questions and OPT record.
        needed: usize,
    },
    /// An NSEC/NSEC3 type bitmap violates RFC 4034 section 4.1.2.
    #[error("invalid type bitmap: {reason}")]
    InvalidTypeBitmap {
        /// Short static description of the violated rule.
        reason: &'static str,
    },
    /// The DS digest type is not supported.
    #[error("unsupported DS digest type {digest_type}")]
    UnsupportedDigestType {
        /// The DS digest type code.
        digest_type: u8,
    },
    /// The NSEC3 hash algorithm is not supported (only 1, SHA-1, exists).
    #[error("unsupported NSEC3 hash algorithm {algorithm}")]
    UnsupportedNsec3Algorithm {
        /// The NSEC3 hash algorithm code.
        algorithm: u8,
    },
    /// The NSEC3 iteration count exceeds the caller's limit (RFC 9276).
    #[error("NSEC3 iteration count {iterations} exceeds the limit of {max}")]
    Nsec3IterationsTooHigh {
        /// Iteration count found.
        iterations: u16,
        /// The limit that was enforced.
        max: u16,
    },
    /// A base32hex string is malformed.
    #[error("invalid base32hex string")]
    InvalidBase32,
    /// An RRset or RRSIG cannot be turned into DNSSEC signing input.
    #[error("invalid RRset for signing input: {reason}")]
    InvalidRrset {
        /// Short static description of the violated rule.
        reason: &'static str,
    },
    /// The RRSIG Labels field exceeds the label count of the owner name.
    #[error("RRSIG labels {labels} exceed the {owner_labels} labels of the owner name")]
    RrsigLabelsTooMany {
        /// RRSIG Labels field.
        labels: u8,
        /// Labels in the owner name.
        owner_labels: usize,
    },
    /// The canonical RDATA form is not implemented for this record type.
    #[error("canonical form of type {rtype} is not supported")]
    UnsupportedCanonicalType {
        /// Numeric record type.
        rtype: u16,
    },
}

impl ProtoError {
    /// Stable, locale-neutral code for the error.
    pub fn code(&self) -> &'static str {
        match self {
            Self::LabelTooLong { .. } => "proto.label_too_long",
            Self::NameTooLong { .. } => "proto.name_too_long",
            Self::EmptyLabel => "proto.empty_label",
            Self::InvalidEscape => "proto.invalid_escape",
            Self::Truncated { .. } => "proto.truncated",
            Self::OffsetOutOfBounds { .. } => "proto.offset_out_of_bounds",
            Self::ReservedLabelType { .. } => "proto.reserved_label_type",
            Self::PointerLoop { .. } => "proto.pointer_loop",
            Self::ForwardPointer { .. } => "proto.forward_pointer",
            Self::TooManyPointers => "proto.too_many_pointers",
            Self::RdataLengthMismatch { .. } => "proto.rdata_length_mismatch",
            Self::InvalidRdata { .. } => "proto.invalid_rdata",
            Self::SvcbKeyOrder { .. } => "proto.svcb_key_order",
            Self::CountsExceedData { .. } => "proto.counts_exceed_data",
            Self::DuplicateOpt => "proto.duplicate_opt",
            Self::MisplacedOpt { .. } => "proto.misplaced_opt",
            Self::OptOwnerNotRoot => "proto.opt_owner_not_root",
            Self::TrailingData { .. } => "proto.trailing_data",
            Self::InvalidEdns { .. } => "proto.invalid_edns",
            Self::InvalidMessage { .. } => "proto.invalid_message",
            Self::LimitTooSmall { .. } => "proto.limit_too_small",
            Self::InvalidTypeBitmap { .. } => "proto.invalid_type_bitmap",
            Self::UnsupportedDigestType { .. } => "proto.unsupported_digest_type",
            Self::UnsupportedNsec3Algorithm { .. } => "proto.unsupported_nsec3_algorithm",
            Self::Nsec3IterationsTooHigh { .. } => "proto.nsec3_iterations_too_high",
            Self::InvalidBase32 => "proto.invalid_base32",
            Self::InvalidRrset { .. } => "proto.invalid_rrset",
            Self::RrsigLabelsTooMany { .. } => "proto.rrsig_labels_too_many",
            Self::UnsupportedCanonicalType { .. } => "proto.unsupported_canonical_type",
        }
    }
}
