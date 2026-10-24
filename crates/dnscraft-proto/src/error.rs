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
        }
    }
}
