use std::marker::PhantomData;

use crate::wireshark::{find_dissector, DissectorTrait, Tree};

/// Additional data which may be passed to the ethertype dissector.
///
/// Example
///
/// ```rust
/// use wsdf::wireshark::{Dissector, DissectorTrait, Encoding, EthertypeData, EthertypeDissector};
///
/// let dissector = Dissector::new(|tree, tvb| {
///     let ethertype_range = tvb.range(0, 2)?;
///     let ethertype_value = ethertype_range.uint16(Encoding::BigEndian)?;
///
///     if let Some(ethertype_dissector) = EthertypeDissector::new() {
///         let ethertype_data = EthertypeData {
///             etype: ethertype_value,
///             payload_offset: ethertype_range.length(),
///             fh_tree: &tree,
///             trailer_id: 0,
///             fcs_len: 0,
///         };
///         ethertype_dissector.call_with_data(
///             &tvb,
///             &tree.pinfo,
///             tree,
///             ethertype_data,
///         )?;
///     }
///     Ok(tvb.captured_length()) // Return captured bytes
/// });
/// ```
pub struct EthertypeData<'a> {
    pub etype: u16,
    pub payload_offset: i32,
    pub fh_tree: &'a Tree<'a>,
    pub trailer_id: i32,
    pub fcs_len: i32,
}

impl<'a> EthertypeData<'a> {
    /// Creates a new `EthertypeData` object for the given `Tree`.
    pub fn new(tree: &'a Tree) -> Self {
        Self {
            etype: 0,
            payload_offset: 0,
            fh_tree: tree,
            trailer_id: 0,
            fcs_len: 0,
        }
    }
}

impl<'a> std::convert::From<EthertypeData<'a>> for epan_sys::ethertype_data_t {
    fn from(value: EthertypeData<'a>) -> Self {
        epan_sys::ethertype_data_s {
            etype: value.etype,
            payload_offset: value.payload_offset,
            fh_tree: value.fh_tree.current_node,
            trailer_id: value.trailer_id,
            fcs_len: value.fcs_len,
        }
    }
}

pub struct EthertypeDissector<'a> {
    ptr: epan_sys::dissector_handle_t,
    phantom: PhantomData<&'a epan_sys::dissector_handle_t>,
}

impl<'a> EthertypeDissector<'a> {
    pub const NAME: &'static str = "ethertype";

    pub fn new() -> Option<EthertypeDissector<'a>> {
        find_dissector(Self::NAME).map(From::from)
    }
}

impl<'a> DissectorTrait for EthertypeDissector<'a> {
    type CData = epan_sys::ethertype_data_t;
    type Data = EthertypeData<'a>;

    fn as_ptr(&self) -> epan_sys::dissector_handle_t {
        self.ptr
    }
}

impl<'a> From<epan_sys::dissector_handle_t> for EthertypeDissector<'a> {
    fn from(value: epan_sys::dissector_handle_t) -> Self {
        Self {
            ptr: value,
            phantom: PhantomData,
        }
    }
}
