use super::{protocol::*, types::*};
use epan_sys;
use std::{
    ffi::{c_char, c_int, c_void},
    fmt::Debug,
    hash::Hash,
    marker::PhantomData,
    ptr::NonNull,
};

pub trait DissectorTrait {
    /// C type containing extra data to pass to a dissector.
    ///
    /// Type the upstream dissector uses.
    type CData;

    /// Type containing extra data to pass to a dissector.
    ///
    /// May be a Rust definition of a type which can be converted to `Self::CData`.
    /// If such a type does not exist, this may be the same as `Self::CData`.
    type Data: Into<Self::CData>;

    /// Returns a pointer to the underlying dissector handle
    fn as_ptr(&self) -> epan_sys::dissector_handle_t;

    /// Calls the dissector using a handle.
    ///
    /// Returns an error if the protocol is disabled or another error occurred
    /// while the dissector was running. Otherwise, if the handle refers to a new-style
    /// dissector, calls the dissector and returns its return value; otherwise
    /// calls it and returns the length of the provided `Tvb` argument.
    fn call(
        &self,
        tvb: &Tvb,
        pinfo: &PacketInfo,
        tree: &Tree,
    ) -> Result<i32, DissectorHandleError> {
        let result = unsafe {
            epan_sys::call_dissector(self.as_ptr(), tvb.as_ptr(), pinfo.ptr, tree.current_node)
        };

        match result {
            r if r < 0 => Err(DissectorHandleError::Unspecified(result)),
            0 => Err(DissectorHandleError::Disabled),
            _ => Ok(result),
        }
    }

    /// Calls the dissector, passing additional dissector parameters inside `dissector_data`.
    ///
    /// The type of the `dissector_data` argument is specific to the dissector being
    /// called.
    ///
    /// Returns an error if the protocol is disabled or another error occurred
    /// while the dissector was running. Otherwise, if the handle refers to a new-style
    /// dissector, calls the dissector and returns its return value; otherwise
    /// calls it and returns the length of the provided `Tvb` argument.
    fn call_with_data(
        &self,
        tvb: &Tvb,
        pinfo: &PacketInfo,
        tree: &Tree,
        dissector_data: Self::Data,
    ) -> Result<i32, DissectorHandleError> {
        let dissector_data: Self::CData = dissector_data.into();
        let result = unsafe {
            epan_sys::call_dissector_with_data(
                self.as_ptr(),
                tvb.as_ptr(),
                pinfo.ptr,
                tree.current_node,
                core::ptr::from_ref(&dissector_data) as *mut c_void,
            )
        };

        match result {
            r if r < 0 => Err(DissectorHandleError::Unspecified(result)),
            0 => Err(DissectorHandleError::Disabled),
            _ => Ok(result),
        }
    }
}

/// A packet dissector implementation using the new TvbRange API.
///
/// Dissectors contain the logic for analyzing packet contents and building
/// the protocol tree. The new API matches Wireshark's Lua patterns for familiarity.
///
/// # Example
///
/// ```rust,no_run
/// use wsdf::wireshark::Dissector;
/// let dissector = Dissector::new(|tree, tvb| {
///     // Create ranges for data access. Analogous to Lua API tvb(offset, length)
///     // Reference: wslua_tvb.c Tvb_range()
///     let version_range = tvb.range(0, 1)?;
///     let header_range = tvb.range(1, 8)?;
///
///     // Add to tree using ranges. Analogous to Lua API tree:add(field, range)
///     // Reference: wslua_tree.c TreeItem_add()
///     tree.add_item("version", version_range)?;
///     let mut header_tree = tree.add("header", header_range)?;
///
///     // Extract values from ranges. Analogous to Lua API range:uint()
///     // Reference: wslua_tvb.c TvbRange_uint()
///     let version = version_range.uint8()?;
///
///     Ok(tvb.reported_length()) // Return consumed bytes
/// });
/// ```
type DissectorFn = Box<dyn Fn(&mut Tree, Tvb) -> Result<i32, Box<dyn std::error::Error>>>;

pub struct Dissector {
    inner: DissectorFn,
}

impl Dissector {
    pub fn new<F>(f: F) -> Self
    where
        F: Fn(&mut Tree, Tvb) -> Result<i32, Box<dyn std::error::Error>> + 'static,
    {
        Dissector { inner: Box::new(f) }
    }

    // This is where wireshark presents a packet to the ffi interface
    pub(crate) unsafe fn process_packet(
        &self,
        tvb: *mut epan_sys::tvbuff,
        pinfo: *mut epan_sys::packet_info,
        proto_tree: *mut epan_sys::proto_tree,
        protocol: &Protocol,
    ) -> c_int {
        let tree_result = Tree::new(protocol, pinfo, proto_tree, tvb, 0);
        match tree_result {
            Ok((mut tree, tvb_wrapper)) => (self.inner)(&mut tree, tvb_wrapper).unwrap_or_default(),
            Err(_) => 0, // Error creating tree
        }
    }
}

/// Immutable reference to packet data - matches C tvbuff_t*
/// This represents a view into packet data without any dissector state
#[derive(Clone, Copy)]
pub struct Tvb {
    ptr: *mut epan_sys::tvbuff,
}

impl Tvb {
    pub fn new(ptr: *mut epan_sys::tvbuff) -> Self {
        Self { ptr }
    }

    /// Get the total reported length of this TVB
    pub fn reported_length(&self) -> i32 {
        unsafe { epan_sys::tvb_reported_length(self.ptr) as i32 }
    }

    /// Get the captured length of this TVB
    pub fn captured_length(&self) -> i32 {
        unsafe { epan_sys::tvb_captured_length(self.ptr) as i32 }
    }

    /// Get remaining reported length from offset
    pub fn reported_length_remaining(&self, offset: i32) -> i32 {
        unsafe { epan_sys::tvb_reported_length_remaining(self.ptr, offset) }
    }

    /// Get remaining captured length from offset
    pub fn captured_length_remaining(&self, offset: i32) -> i32 {
        unsafe { epan_sys::tvb_captured_length_remaining(self.ptr, offset) }
    }

    /// Create a TvbRange from this TVB. Analogous to Lua API tvb(offset, length)
    /// Reference: wslua_tvb.c Tvb_range()
    pub fn range(&self, offset: i32, length: i32) -> Result<TvbRange, TvbError> {
        if offset < 0 {
            return Err(TvbError::InvalidRange);
        }

        let actual_length = if length == -1 {
            self.reported_length_remaining(offset)
        } else {
            if length < 0 {
                return Err(TvbError::InvalidRange);
            }
            length
        };

        if actual_length < 0 {
            return Err(TvbError::OutOfBounds);
        }

        if offset + actual_length > self.reported_length() {
            return Err(TvbError::OutOfBounds);
        }

        Ok(TvbRange {
            tvb: *self,
            offset,
            length: actual_length,
        })
    }

    /// Create a range covering the entire TVB
    pub fn range_all(&self) -> TvbRange {
        TvbRange {
            tvb: *self,
            offset: 0,
            length: self.reported_length(),
        }
    }

    /// Create subset TVB with specified length
    pub fn subset_length(&self, offset: i32, length: i32) -> Result<Tvb, TvbError> {
        unsafe {
            let tvb = epan_sys::tvb_new_subset_length(self.ptr, offset, length);
            if tvb.is_null() {
                Err(TvbError::SubsetFailed)
            } else {
                Ok(Tvb { ptr: tvb })
            }
        }
    }

    /// Create subset TVB from offset to end
    pub fn subset_remaining(&self, offset: i32) -> Result<Tvb, TvbError> {
        unsafe {
            let tvb = epan_sys::tvb_new_subset_remaining(self.ptr, offset);
            if tvb.is_null() {
                Err(TvbError::SubsetFailed)
            } else {
                Ok(Tvb { ptr: tvb })
            }
        }
    }

    /// Create child TVB with new data
    ///
    /// # Safety
    /// `data` must be valid for `length` bytes and outlive the returned `Tvb`.
    pub unsafe fn new_child_real_data(
        &self,
        data: *const u8,
        length: u32,
        reported_length: u32,
    ) -> Result<Tvb, TvbError> {
        let tvb = epan_sys::tvb_new_child_real_data(
            self.ptr,
            data as *mut u8,
            length,
            reported_length as i32,
        );

        if tvb.is_null() {
            Err(TvbError::SubsetFailed)
        } else {
            Ok(Tvb { ptr: tvb })
        }
    }

    /// Get raw pointer to data at `offset` for `length` bytes.
    ///
    /// # Safety
    /// `offset` and `length` must be within the bounds of this TVB.
    pub unsafe fn get_ptr(&self, offset: i32, length: i32) -> *const u8 {
        epan_sys::tvb_get_ptr(self.ptr, offset, length)
    }

    /// Internal getter for the raw pointer
    pub(crate) fn as_ptr(&self) -> *mut epan_sys::tvbuff {
        self.ptr
    }
}

/// Lightweight view into a TVB. Analogous to Lua API TvbRange concept
/// Reference: wslua_tvb.c TvbRange struct and methods
/// This is where the actual data extraction happens
#[derive(Clone, Copy)]
pub struct TvbRange {
    tvb: Tvb,
    offset: i32,
    length: i32,
}

impl TvbRange {
    /// Get the underlying TVB
    pub fn tvb(&self) -> Tvb {
        self.tvb
    }

    /// Get the offset within the TVB
    pub fn offset(&self) -> i32 {
        self.offset
    }

    /// Get the length of this range
    pub fn length(&self) -> i32 {
        self.length
    }

    /// Create a sub-range within this range
    pub fn range(&self, offset: i32, length: i32) -> Result<TvbRange, TvbError> {
        if offset < 0 {
            return Err(TvbError::InvalidRange);
        }

        let actual_length = if length == -1 {
            self.length - offset
        } else {
            if length < 0 {
                return Err(TvbError::InvalidRange);
            }
            length
        };

        if actual_length < 0 || offset + actual_length > self.length {
            return Err(TvbError::OutOfBounds);
        }

        Ok(TvbRange {
            tvb: self.tvb,
            offset: self.offset + offset,
            length: actual_length,
        })
    }

    /// Extract uint8 from this range. Analogous to Lua API TvbRange:uint()
    /// Reference: wslua_tvb.c TvbRange_uint()
    pub fn uint8(&self) -> Result<u8, TvbError> {
        if self.length < 1 {
            return Err(TvbError::InvalidLength {
                expected: 1,
                actual: self.length,
            });
        }
        unsafe { Ok(epan_sys::tvb_get_uint8(self.tvb.ptr, self.offset)) }
    }

    /// Extract uint16 with endianness
    pub fn uint16(&self, encoding: Encoding) -> Result<u16, TvbError> {
        if self.length < 2 {
            return Err(TvbError::InvalidLength {
                expected: 2,
                actual: self.length,
            });
        }
        unsafe {
            let value = match encoding {
                Encoding::BigEndian => epan_sys::tvb_get_ntohs(self.tvb.ptr, self.offset),
                Encoding::LittleEndian => epan_sys::tvb_get_letohs(self.tvb.ptr, self.offset),
                _ => return Err(TvbError::InvalidEncoding),
            };
            Ok(value)
        }
    }

    /// Extract 24 bits into a 32-bit unsigned integer with endianness
    pub fn uint24(&self, encoding: Encoding) -> Result<u32, TvbError> {
        if self.length < 3 {
            return Err(TvbError::InvalidLength {
                expected: 3,
                actual: self.length,
            });
        }
        unsafe {
            let value = match encoding {
                Encoding::BigEndian => epan_sys::tvb_get_ntoh24(self.tvb.ptr, self.offset),
                Encoding::LittleEndian => epan_sys::tvb_get_letoh24(self.tvb.ptr, self.offset),
                _ => return Err(TvbError::InvalidEncoding),
            };
            Ok(value)
        }
    }

    /// Extract uint32 with endianness
    pub fn uint32(&self, encoding: Encoding) -> Result<u32, TvbError> {
        if self.length < 4 {
            return Err(TvbError::InvalidLength {
                expected: 4,
                actual: self.length,
            });
        }
        unsafe {
            let value = match encoding {
                Encoding::BigEndian => epan_sys::tvb_get_ntohl(self.tvb.ptr, self.offset),
                Encoding::LittleEndian => epan_sys::tvb_get_letohl(self.tvb.ptr, self.offset),
                _ => return Err(TvbError::InvalidEncoding),
            };
            Ok(value)
        }
    }

    /// Get raw bytes as Vec. Analogous to Lua API TvbRange:bytes()
    /// Reference: wslua_tvb.c TvbRange_bytes()
    pub fn bytes(&self) -> Vec<u8> {
        unsafe {
            let ptr = epan_sys::tvb_get_ptr(self.tvb.ptr, self.offset, self.length);
            // `tvb_get_ptr` may return `null` if the specified length is zero.
            // `from_raw_parts` will fail if the pointer argument is `null`, so check
            // it's validity first and return a default `Vec` it's invalid.
            if ptr.is_null() || !ptr.is_aligned() {
                Vec::default()
            } else {
                std::slice::from_raw_parts(ptr, self.length as usize).to_vec()
            }
        }
    }

    /// Create subset TVB from this range. Analogous to Lua API TvbRange:tvb()
    /// Reference: wslua_tvb.c TvbRange_tvb()
    pub fn to_tvb(&self) -> Result<Tvb, TvbError> {
        self.tvb.subset_length(self.offset, self.length)
    }

    /// Get string with encoding. Analogous to Lua API TvbRange:string()
    /// Reference: wslua_tvb.c TvbRange_string()
    pub fn string(&self, encoding: Encoding) -> Result<String, TvbError> {
        let bytes = self.bytes();
        match encoding {
            Encoding::UTF8 => String::from_utf8(bytes).map_err(|_| TvbError::InvalidEncoding),
            Encoding::ASCII7Bits => {
                // Convert ASCII bytes to string
                if bytes.iter().all(|&b| b <= 127) {
                    Ok(String::from_utf8_lossy(&bytes).to_string())
                } else {
                    Err(TvbError::InvalidEncoding)
                }
            }
            _ => Err(TvbError::InvalidEncoding), // TODO: Add more encoding support
        }
    }

    /// Check if bytes exist without throwing. Analogous to Lua API bounds checking
    /// Reference: wslua_tvb.c push_TvbRange() bounds validation
    pub fn bytes_exist(&self) -> bool {
        unsafe { epan_sys::tvb_bytes_exist(self.tvb.ptr, self.offset, self.length) }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Address {
    inner: epan_sys::address,
}

impl Address {
    pub fn new(address: epan_sys::address) -> Self {
        Self { inner: address }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, AddressError> {
        let length: u32 = self.inner.len.try_into()?;
        let mut buffer = vec![0u8; length as usize];

        let copy_length = unsafe {
            epan_sys::address_to_bytes(std::ptr::from_ref(&self.inner), buffer.as_mut_ptr(), length)
        };

        if copy_length == length {
            Ok(buffer)
        } else {
            Err(AddressError::CopyFailed)
        }
    }
}

impl Hash for Address {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.inner.type_.hash(state);
        self.inner.data.hash(state);
        self.inner.len.hash(state);
    }
}

impl PartialEq for Address {
    fn eq(&self, other: &Self) -> bool {
        self.inner.type_ == other.inner.type_
            && self.inner.len == other.inner.len
            && (self.inner.len == 0
                || (self.inner.data.is_null() && other.inner.data.is_null())
                || (!self.inner.data.is_null()
                    && self.inner.data.is_aligned()
                    && !other.inner.data.is_null()
                    && other.inner.data.is_aligned()
                    && unsafe {
                        std::slice::from_raw_parts(
                            self.inner.data as *const u8,
                            self.inner.len as usize,
                        ) == std::slice::from_raw_parts(
                            other.inner.data as *const u8,
                            other.inner.len as usize,
                        )
                    }))
    }
}

#[derive(Clone, Copy)]
pub struct PacketInfo {
    ptr: *mut epan_sys::_packet_info,
}
impl PacketInfo {
    pub fn new(ptr: *mut epan_sys::_packet_info) -> Self {
        Self { ptr }
    }
    /// # Safety
    /// Caller must ensure `self.ptr` points to a live `packet_info` with a valid `pool`.
    pub unsafe fn alloc_string(&self, s: &str) -> *const c_char {
        let c_str = std::ffi::CString::new(s).expect("msg");
        unsafe {
            let size = s.len() + 1; // +1 for null terminator
            let ptr = epan_sys::wmem_alloc((*self.ptr).pool, size) as *mut c_char;
            std::ptr::copy_nonoverlapping(c_str.as_ptr(), ptr, size);
            ptr
        }
    }
    /// # Safety
    /// Caller must ensure `self.ptr` points to a live `packet_info` with a valid `pool`.
    pub unsafe fn alloc_bytes(&self, bytes: &[u8]) -> *mut u8 {
        unsafe {
            let ptr = epan_sys::wmem_alloc((*self.ptr).pool, bytes.len()) as *mut u8;
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
            ptr
        }
    }
    pub fn set_column_text(&self, col: Column, text: &str) {
        unsafe {
            let text = self.alloc_string(text);
            epan_sys::col_clear((*self.ptr).cinfo, col as i32);
            epan_sys::col_add_str((*self.ptr).cinfo, col as i32, text);
        }
    }
    pub fn clear_column(&self, col: Column) {
        unsafe {
            epan_sys::col_clear((*self.ptr).cinfo, col as i32);
        }
    }
    /// # Safety
    /// `self.ptr` and `tvb` must be valid for the duration of the call.
    pub unsafe fn add_data_source(&self, tvb: &Tvb, name: &str) {
        let name = self.alloc_string(name);
        epan_sys::add_new_data_source(self.ptr, tvb.as_ptr(), name);
    }
    pub fn set_fragmented(&self, fragmented: bool) {
        unsafe { (*self.ptr).fragmented = fragmented }
    }
    pub fn fd_visited(&self) -> bool {
        match unsafe { (*self.ptr).fd.as_ref() } {
            Some(frame_data) => frame_data.visited() > 0,
            None => panic!("frame data point is NULL"),
        }
    }
    pub fn set_fd_visited(&self, value: bool) {
        match unsafe { (*self.ptr).fd.as_mut() } {
            Some(frame_data) => {
                let value = if value { 1 } else { 0 };
                frame_data.set_visited(value);
            }
            None => panic!("frame data point is NULL"),
        }
    }

    pub fn dl_src(&'_ self) -> Address {
        Address::new(unsafe { (*self.ptr).dl_src })
    }

    pub fn dl_dst(&'_ self) -> Address {
        Address::new(unsafe { (*self.ptr).dl_dst })
    }

    pub fn src(&'_ self) -> Address {
        Address::new(unsafe { (*self.ptr).src })
    }

    pub fn dst(&'_ self) -> Address {
        Address::new(unsafe { (*self.ptr).dst })
    }
}

/// Tree represents a protocol tree node that can have children added to it.
/// Analogous to Lua API TreeItem concept - it's both an item and potential container
/// Reference: wslua_tree.c TreeItem struct and methods
pub struct Tree<'a> {
    protocol: &'a Protocol,
    pub pinfo: PacketInfo,
    pub(crate) current_node: *mut epan_sys::proto_node, // The subtree for adding children to
    current_item: *mut epan_sys::proto_item,            // The item itself
}

impl<'a> Tree<'a> {
    /// Create the root tree for a protocol dissector
    /// This should be called at the start of dissection
    pub(crate) unsafe fn new(
        protocol: &'a Protocol,
        pinfo: *mut epan_sys::packet_info,
        parent: *mut epan_sys::proto_node,
        tvb: *mut epan_sys::tvbuff,
        offset: i32,
    ) -> TreeResult<(Self, Tvb)> {
        let item = epan_sys::proto_tree_add_item(
            parent,
            protocol.get_proto_handle(),
            tvb,
            offset,
            -1,
            epan_sys::ENC_NA,
        );

        let ett_handle = protocol
            .get_ett_handle(ROOT_ETT_ID)
            .ok_or(TreeError::EttNotFound(format!(
                "Ett '{}' not found",
                ROOT_ETT_ID
            )))?;

        // The actual subtree for display
        let current = epan_sys::proto_item_add_subtree(item, ett_handle);

        let tree = Self {
            protocol,
            pinfo: PacketInfo::new(pinfo),
            current_node: current,
            current_item: item,
        };

        let tvb_wrapper = Tvb::new(tvb);

        Ok((tree, tvb_wrapper))
    }
    /// Add child item to tree using TvbRange. Analogous to Lua API tree:add(field, range)
    /// Reference: wslua_tree.c TreeItem_add()
    pub fn add(&mut self, field_id: &str, range: TvbRange) -> TreeResult<Tree<'a>> {
        let field_handle = self
            .protocol
            .get_field_handle(field_id)
            .ok_or_else(|| TreeError::AddItemFailed(format!("Field '{}' not found", field_id)))?;

        if !range.bytes_exist() {
            return Err(TreeError::AddItemFailed(
                "TvbRange extends beyond packet data".into(),
            ));
        }

        unsafe {
            let item = epan_sys::proto_tree_add_item(
                self.current_node,
                field_handle.handle,
                range.tvb.as_ptr(),
                range.offset,
                range.length,
                epan_sys::ENC_NA,
            );

            // Get the field's ETT for creating subtree (or use a default)
            let ett_handle = self
                .protocol
                .get_ett_handle(&format!("{}_ett", field_id))
                .or_else(|| self.protocol.get_ett_handle(ROOT_ETT_ID))
                .ok_or(TreeError::EttNotFound("No suitable ETT found".into()))?;

            // Convert item to subtree (Lua pattern!)
            let subtree = epan_sys::proto_item_add_subtree(item, ett_handle);

            Ok(Tree {
                protocol: self.protocol,
                pinfo: self.pinfo,
                current_node: subtree,
                current_item: item,
            })
        }
    }

    /// Add child item with specific encoding. Analogous to Lua API tree:add(field, range, encoding)
    /// Reference: wslua_tree.c TreeItem_add()
    pub fn add_with_encoding(
        &mut self,
        field_id: &str,
        range: TvbRange,
        encoding: Encoding,
    ) -> TreeResult<Tree<'a>> {
        let field_handle = self
            .protocol
            .get_field_handle(field_id)
            .ok_or_else(|| TreeError::AddItemFailed(format!("Field '{}' not found", field_id)))?;

        if !range.bytes_exist() {
            return Err(TreeError::AddItemFailed(
                "TvbRange extends beyond packet data".into(),
            ));
        }

        unsafe {
            let item = epan_sys::proto_tree_add_item(
                self.current_node,
                field_handle.handle,
                range.tvb.as_ptr(),
                range.offset,
                range.length,
                encoding.to_u32(),
            );

            // Get the field's ETT for creating subtree
            let ett_handle = self
                .protocol
                .get_ett_handle(&format!("{}_ett", field_id))
                .or_else(|| self.protocol.get_ett_handle(ROOT_ETT_ID))
                .ok_or(TreeError::EttNotFound("No suitable ETT found".into()))?;

            // Convert item to subtree (Lua pattern!)
            let subtree = epan_sys::proto_item_add_subtree(item, ett_handle);

            Ok(Tree {
                protocol: self.protocol,
                pinfo: self.pinfo,
                current_node: subtree,
                current_item: item,
            })
        }
    }

    /// Add item and return TreeItem for expert info, text setting, etc.
    /// Analogous to Lua API tree:add() returning a TreeItem
    /// Reference: wslua_tree.c TreeItem_add()
    pub fn add_item(&mut self, field_id: &str, range: TvbRange) -> TreeResult<TreeItem> {
        let field_handle = self
            .protocol
            .get_field_handle(field_id)
            .ok_or_else(|| TreeError::AddItemFailed(format!("Field '{}' not found", field_id)))?;

        if !range.bytes_exist() {
            return Err(TreeError::AddItemFailed(
                "TvbRange extends beyond packet data".into(),
            ));
        }

        unsafe {
            let item = epan_sys::proto_tree_add_item(
                self.current_node,
                field_handle.handle,
                range.tvb.as_ptr(),
                range.offset,
                range.length,
                epan_sys::ENC_NA,
            );

            Ok(TreeItem::new(item, self.pinfo))
        }
    }

    /// Add item with encoding and return TreeItem
    pub fn add_item_with_encoding(
        &mut self,
        field_id: &str,
        range: TvbRange,
        encoding: Encoding,
    ) -> TreeResult<TreeItem> {
        let field_handle = self
            .protocol
            .get_field_handle(field_id)
            .ok_or_else(|| TreeError::AddItemFailed(format!("Field '{}' not found", field_id)))?;

        if !range.bytes_exist() {
            return Err(TreeError::AddItemFailed(
                "TvbRange extends beyond packet data".into(),
            ));
        }

        unsafe {
            let item = epan_sys::proto_tree_add_item(
                self.current_node,
                field_handle.handle,
                range.tvb.as_ptr(),
                range.offset,
                range.length,
                encoding.to_u32(),
            );

            Ok(TreeItem::new(item, self.pinfo))
        }
    }
    pub fn add_expert_info(
        &mut self,
        item: &mut TreeItem,
        expert_id: &str,
        text: Option<&str>,
    ) -> Result<(), ExpertError> {
        let handle = self
            .protocol
            .get_expert_field(expert_id)
            .ok_or_else(|| ExpertError::FieldNotFound(expert_id.to_string()))?;

        unsafe {
            let mut expert_field = epan_sys::expert_field {
                ei: handle.ei,
                hf: handle.hf,
            };
            if let Some(text) = text {
                // Custom text
                let text_ptr = self.pinfo.alloc_string(text);
                epan_sys::expert_add_info_format(
                    self.pinfo.ptr,
                    item.as_ptr(),
                    &mut expert_field as *mut epan_sys::expert_field,
                    text_ptr,
                );
            } else {
                // Default text from registration
                epan_sys::expert_add_info(
                    self.pinfo.ptr,
                    item.as_ptr(),
                    &mut expert_field as *mut epan_sys::expert_field,
                );
            }
        }
        Ok(())
    }
    /// Set custom text on tree item
    pub fn set_text(&mut self, text: &str) {
        unsafe {
            let text_ptr = self.pinfo.alloc_string(text);
            epan_sys::proto_item_set_text(self.current_item, text_ptr);
        }
    }

    /// Append text to tree item
    pub fn append_text(&mut self, text: &str) {
        unsafe {
            let text_ptr = self.pinfo.alloc_string(text);
            epan_sys::proto_item_append_text(self.current_item, text_ptr);
        }
    }

    /// Set the length of this tree item (rarely needed with TvbRange)
    pub fn set_length(&mut self, length: i32) {
        unsafe {
            epan_sys::proto_item_set_len(self.current_item, length);
        }
    }

    /// Transform data from TvbRange (for decompression, decoding, etc.)
    pub fn transform_data(
        &self,
        range: TvbRange,
        transform_fn: impl FnOnce(&[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>>,
        name: &str,
    ) -> Result<Tvb, Box<dyn std::error::Error>> {
        let src_data = range.bytes();
        let dst_data = transform_fn(&src_data)?;

        unsafe {
            // Allocate memory for the lifetime of the packet
            let dst_ptr = self.pinfo.alloc_bytes(&dst_data);
            let next_tvb = range.tvb.new_child_real_data(
                dst_ptr,
                dst_data.len() as u32,
                dst_data.len() as u32,
            )?;

            self.pinfo.add_data_source(&next_tvb, name);

            Ok(next_tvb)
        }
    }

    /// Returns a reference to this tree's Protocol
    pub fn protocol(&self) -> &Protocol {
        self.protocol
    }

    pub fn process_reassembled_data(
        &self,
        tvb_range: TvbRange,
        name: &'static str,
        fd_head: Option<FragmentHead>,
        update_col_infop: Option<bool>,
    ) -> Option<Tvb> {
        let fd_head = match fd_head {
            Some(fd_head) => fd_head.ptr.as_ptr(),
            None => core::ptr::null_mut(),
        };

        let update_col_infop = match update_col_infop {
            Some(update_col_infop) => core::ptr::from_ref(&update_col_infop) as *mut bool,
            None => core::ptr::null_mut(),
        };

        // Creating fragment_items in two steps like this ensures the values pointed to by
        // the inner fields of `epan_sys::fragment_items` are valid until the end of this block.
        let mut fragment_items = self.protocol.get_fragment_items()?;
        let mut items: FragmentItems = (&mut fragment_items).into();

        let new_tvb = unsafe {
            epan_sys::process_reassembled_data(
                tvb_range.tvb.ptr,
                tvb_range.offset,
                self.pinfo.ptr,
                to_c_str(name),
                fd_head,
                items.as_ptr(),
                update_col_infop,
                self.current_node,
            )
        };

        NonNull::new(new_tvb).map(|inner| Tvb::new(inner.as_ptr()))
    }
}

/// TreeItem represents a single protocol item in the tree
/// Used for setting text, adding expert info, etc.
#[derive(Clone, Copy)]
pub struct TreeItem {
    ptr: *mut epan_sys::proto_item,
    pub pinfo: PacketInfo,
}

impl TreeItem {
    pub(crate) fn new(ptr: *mut epan_sys::proto_item, pinfo: PacketInfo) -> Self {
        Self { ptr, pinfo }
    }

    /// Set custom text on this item
    pub fn set_text(&mut self, text: &str) {
        unsafe {
            let text_ptr = self.pinfo.alloc_string(text);
            epan_sys::proto_item_set_text(self.ptr, text_ptr);
        }
    }

    /// Append text to this item
    pub fn append_text(&mut self, text: &str) {
        unsafe {
            let text_ptr = self.pinfo.alloc_string(text);
            epan_sys::proto_item_append_text(self.ptr, text_ptr);
        }
    }

    /// Set the length of this item
    pub fn set_length(&mut self, length: i32) {
        unsafe {
            epan_sys::proto_item_set_len(self.ptr, length);
        }
    }

    /// Internal getter for FFI
    pub(crate) fn as_ptr(&self) -> *mut epan_sys::proto_item {
        self.ptr
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FragmentHead {
    ptr: NonNull<epan_sys::fragment_head>,
}

#[derive(Debug)]
pub struct ReassemblyTable<T> {
    inner: epan_sys::reassembly_table,
    type_phantom: PhantomData<T>,
}

impl<T> ReassemblyTable<T> {
    pub fn init(reassembly_table_functions: &epan_sys::reassembly_table_functions) -> Self {
        let mut reassembly_table = epan_sys::reassembly_table {
            fragment_table: std::ptr::null_mut(),
            reassembled_table: std::ptr::null_mut(),
            temporary_key_func: None,
            persistent_key_func: None,
            free_temporary_key_func: None,
        };

        unsafe {
            epan_sys::reassembly_table_init(
                std::ptr::from_mut(&mut reassembly_table),
                std::ptr::from_ref(reassembly_table_functions),
            );
        }

        Self {
            inner: reassembly_table,
            type_phantom: PhantomData,
        }
    }

    pub fn fragment_add_seq_check(
        &mut self,
        tvb: &TvbRange,
        offset: i32,
        pinfo: &PacketInfo,
        id: u32,
        data: Option<&T>,
        frag_number: u32,
        more_frags: bool,
    ) -> Option<FragmentHead> {
        let data = match data {
            Some(data) => std::ptr::from_ref(data),
            None => std::ptr::null(),
        };

        let fragment_head = unsafe {
            epan_sys::fragment_add_seq_check(
                std::ptr::from_mut(&mut self.inner),
                tvb.tvb.as_ptr(),
                offset,
                pinfo.ptr,
                id,
                data as *const c_void,
                frag_number,
                tvb.length() as u32,
                more_frags,
            )
        };

        NonNull::new(fragment_head).map(|ptr| FragmentHead { ptr })
    }

    pub fn fragment_add_seq_offset(
        &mut self,
        pinfo: &PacketInfo,
        id: u32,
        data: Option<&T>,
        fragment_offset: u32,
    ) {
        let data = match data {
            Some(data) => std::ptr::from_ref(data),
            None => std::ptr::null(),
        };

        unsafe {
            epan_sys::fragment_add_seq_offset(
                std::ptr::from_mut(&mut self.inner),
                pinfo.ptr,
                id,
                data as *const c_void,
                fragment_offset,
            );
        }
    }
}

impl<T> Drop for ReassemblyTable<T> {
    fn drop(&mut self) {
        unsafe { epan_sys::reassembly_table_destroy(std::ptr::from_mut(&mut self.inner)) }
    }
}

// Returns a dissector reference by name if it exists; otherwise returns `None`.
pub fn find_dissector(name: &str) -> Option<epan_sys::dissector_handle_t> {
    let name = std::ffi::CString::new(name).unwrap();
    let handle = unsafe { epan_sys::find_dissector(name.as_ptr()) };
    if handle.is_null() {
        None
    } else {
        Some(handle)
    }
}
