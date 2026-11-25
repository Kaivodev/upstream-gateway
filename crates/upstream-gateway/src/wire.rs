use crate::DESCRIPTOR;
use prost::{
    Message, Name,
    encoding::{WireType, decode_key, decode_varint},
};
use prost_reflect::{DescriptorPool, Kind, MessageDescriptor};
use std::{collections::BTreeSet, sync::LazyLock};
use tonic::Status;

pub const MESSAGE_LIMIT: usize = 16 << 20;
pub static DESCRIPTORS: LazyLock<DescriptorPool> =
    LazyLock::new(|| DescriptorPool::decode(DESCRIPTOR).expect("built-in descriptor"));

pub(crate) fn check_size<M: Message>(value: &M) -> Result<(), Status> {
    size(value.encoded_len())
}
fn size(len: usize) -> Result<(), Status> {
    if len > MESSAGE_LIMIT {
        Err(Status::resource_exhausted("message size limit"))
    } else {
        Ok(())
    }
}

/// Validate every occurrence before prost merges fields and discards unknown tags.
pub fn decode_request<M: Message + Default + Name>(bytes: &[u8]) -> Result<M, Status> {
    size(bytes.len())?;
    let descriptor = DESCRIPTORS
        .get_message_by_name(&M::full_name())
        .ok_or_else(|| Status::internal("missing descriptor"))?;
    inspect(&descriptor, bytes, 0)?;
    M::decode(bytes).map_err(|_| invalid())
}
fn inspect(descriptor: &MessageDescriptor, mut bytes: &[u8], depth: u32) -> Result<(), Status> {
    if depth > 64 {
        return Err(invalid());
    }
    let mut enums = BTreeSet::new();
    while !bytes.is_empty() {
        let (tag, wire) = decode_key(&mut bytes).map_err(|_| invalid())?;
        let kind = descriptor.get_field(tag).ok_or_else(invalid)?.kind();
        match wire {
            WireType::LengthDelimited => {
                let len = usize::try_from(decode_varint(&mut bytes).map_err(|_| invalid())?)
                    .map_err(|_| invalid())?;
                let (field, remaining) = bytes.split_at_checked(len).ok_or_else(invalid)?;
                bytes = remaining;
                match kind {
                    Kind::Message(child) => inspect(&child, field, depth + 1)?,
                    Kind::String | Kind::Bytes => {}
                    _ => return Err(invalid()),
                }
            }
            WireType::Varint => {
                let v = decode_varint(&mut bytes).map_err(|_| invalid())?;
                match kind {
                    Kind::Enum(en)
                        if v != 0 && i32::try_from(v).is_ok_and(|n| en.get_value(n).is_some()) =>
                    {
                        enums.insert(tag);
                    }
                    Kind::Uint32 if u32::try_from(v).is_ok() => {}
                    Kind::Int32 | Kind::Int64 | Kind::Uint64 => {}
                    _ => return Err(invalid()),
                }
            }
            _ => return Err(invalid()),
        }
    }
    if descriptor.fields().any(|f| {
        matches!(f.kind(), Kind::Enum(_))
            && !f.supports_presence()
            && !f.is_list()
            && !enums.contains(&f.number())
    }) {
        return Err(invalid());
    }
    Ok(())
}
pub(crate) fn invalid() -> Status {
    Status::invalid_argument("invalid request")
}

/// The generated server uses this decoder on each complete gRPC message.
#[derive(Default)]
pub struct StrictCodec<T, U>(std::marker::PhantomData<(T, U)>);
pub struct StrictDecoder<U>(std::marker::PhantomData<U>);
impl<T: Message + Default + Send + 'static, U: Message + Name + Default + Send + 'static>
    tonic::codec::Codec for StrictCodec<T, U>
{
    type Encode = T;
    type Decode = U;
    type Encoder = <tonic_prost::ProstCodec<T, U> as tonic::codec::Codec>::Encoder;
    type Decoder = StrictDecoder<U>;
    fn encoder(&mut self) -> Self::Encoder {
        Default::default()
    }
    fn decoder(&mut self) -> Self::Decoder {
        StrictDecoder(std::marker::PhantomData)
    }
}
impl<U: Message + Name + Default> tonic::codec::Decoder for StrictDecoder<U> {
    type Item = U;
    type Error = Status;
    fn decode(&mut self, buf: &mut tonic::codec::DecodeBuf<'_>) -> Result<Option<U>, Status> {
        use bytes::Buf;
        decode_request(&buf.copy_to_bytes(buf.remaining())).map(Some)
    }
}
