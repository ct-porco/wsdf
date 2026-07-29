use super::{dissector::*, plugin::*, types::*};
use epan_sys;
use std::{
    collections::HashMap,
    ffi::{c_int, c_void},
    marker::PhantomData,
    ops::RangeInclusive,
};

/// Defines additional data used to customize the description of a [`Field`]'s value.
///
/// The variant used to customize the description depends on the [`FieldType`].
#[derive(Clone, Debug)]
pub enum FieldConvert {
    /// Used by [`Field`]s with type [`FieldType::Framenum`] to indicate their purpose.
    ///
    /// Wireshark will use the value of the given [`Framenum`] to determine the related
    /// packet symbol to draw.
    Framenum(Framenum),

    /// For [`Field`]s with type [`FieldType::Protocol`] specifies a pointer to a protocol.
    Protocol(*const epan_sys::protocol_t),

    /// For [`Field`]s with a numeric type which might logically fit in ranges of values
    ///
    /// Provide a label for each range the value may fall into. Each [`RangeString`] is
    /// tested in order, so any "catch-all" entries ned to come after more specific
    /// individual entries.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use wsdf::wireshark::{FieldConvert, RangeString};
    ///
    /// let ranges = FieldConvert::RangeStrings(
    ///     vec![
    ///         RangeString{ range: 0..=42, label: "Descriptive String 1".into() },
    ///         RangeString{ range: 43..=u64::MAX, label: "Descriptive String 2".into() },
    ///     ]
    /// );
    /// ```
    RangeStrings(Vec<RangeString>),

    /// For [`Field`]s with type [`FieldType::Boolean`].
    ///
    /// By default boolean fields with a value of `0` are labeled "False" and those
    /// with a value of `1` (or anything else) are labeled "True". This variant allows
    /// those labels to be changed (e.g. "Yes"/"No", "Fast/Slow", etc.).
    ///
    /// # Example
    ///
    /// ```rust
    /// # use wsdf::wireshark::{FieldConvert, TrueFalseString};
    ///
    /// let true_false_string = FieldConvert::TrueFalseString(
    ///     TrueFalseString{ true_string: "Yes", false_string: "No" }
    /// );
    /// ```
    TrueFalseString(TrueFalseString),

    /// Some integer fields (type `FT_UINT*`) need labels to represent the value of a
    /// field. You can think of those fields as having an enumerated data type rather
    /// than an integral data type.
    ///
    /// ```rust
    /// # use wsdf::wireshark::{FieldConvert, ValueString};
    ///
    /// const VAL1: u32 = 0;
    /// const VAL2: u32 = 1;
    ///
    /// let value_strings = FieldConvert::ValueStrings(
    ///     vec![
    ///         ValueString{ value: VAL1, label: "Descriptive String 1".into() },
    ///         ValueString{ value: VAL2, label: "Descriptive String 2".into() },
    ///     ]
    /// );
    /// ```
    ValueStrings(Vec<ValueString>),

    /// Some integer fields (type `FT_UINT*`) need labels to represent the value of a
    /// field. You can think of those fields as having an enumerated data type rather
    /// than an integral data type.
    ///
    /// ```rust
    /// # use wsdf::wireshark::{FieldConvert, Val64String};
    ///
    /// const VAL1: u64 = 0;
    /// const VAL2: u64 = 1;
    ///
    /// let value_strings = FieldConvert::Val64Strings(
    ///     vec![
    ///         Val64String{ value: VAL1, label: "Descriptive String 1".into() },
    ///         Val64String{ value: VAL2, label: "Descriptive String 2".into() },
    ///     ]
    /// );
    /// ```
    Val64Strings(Vec<Val64String>),
}

/// Maps a range of `u64` values to a label.
#[derive(Clone, Debug)]
pub struct RangeString {
    pub range: RangeInclusive<u64>,
    pub label: String,
}

impl From<&RangeString> for epan_sys::range_string {
    fn from(value: &RangeString) -> Self {
        epan_sys::range_string {
            value_min: *value.range.start(),
            value_max: *value.range.end(),
            strptr: to_c_str(&value.label),
        }
    }
}

/// Maps the value `true` and `false` to labels.
#[derive(Clone, Debug)]
pub struct TrueFalseString {
    pub true_string: &'static str,
    pub false_string: &'static str,
}

impl From<&TrueFalseString> for epan_sys::true_false_string {
    fn from(value: &TrueFalseString) -> Self {
        epan_sys::true_false_string {
            true_string: to_c_str(value.true_string),
            false_string: to_c_str(value.false_string),
        }
    }
}

/// Maps a `u32` numeric value to a string.
#[derive(Clone, Debug)]
pub struct ValueString {
    pub value: u32,
    pub label: String,
}

impl From<&ValueString> for epan_sys::value_string {
    fn from(value: &ValueString) -> Self {
        epan_sys::value_string {
            value: value.value,
            strptr: to_c_str(&value.label),
        }
    }
}

/// Maps a `u64` numeric value to a string.
#[derive(Clone, Debug)]
pub struct Val64String {
    pub value: u64,
    pub label: String,
}

impl From<&Val64String> for epan_sys::val64_string {
    fn from(value: &Val64String) -> Self {
        epan_sys::val64_string {
            value: value.value,
            strptr: to_c_str(&value.label),
        }
    }
}

pub struct Protocol {
    _name: String,
    pub abbrev: String,
    filter: String,
    // Static data for this protocol
    pub proto_handle: c_int,

    ett_defs: Vec<Ett>,
    // Holds the collapse state of the subtree
    ett_handles: HashMap<String, EttHandle>,

    // The actual dissector implementation
    pub dissector_fn: Dissector,

    field_defs: Vec<Field>,
    // All registered fields for this protocol
    field_handles: HashMap<String, FieldHandle>,

    // Encapsulates expert fields management under Expert Module
    expert_module: ExpertModule,

    // Pending match conditions for this protocol that have not yet been registered
    pub match_definitions: Option<Vec<DissectorDecodeFrom>>,

    fragment_items: Option<FragmentItemsNames>,
}

impl Protocol {
    unsafe fn register_field(&mut self, field: &Field) -> Result<(), RegistrationError> {
        let mut handle: c_int = -1;

        // For variants which contain a collection of value-label pairs, Wireshark
        // requires the last entry to be a object which has `0` for all numeric fields
        // and `null` for all pointer fields.
        let strings_ptr = match &field.strings {
            Some(FieldConvert::Framenum(framenum)) => {
                // convert this integer to a pointer to that integer
                Box::into_raw(Box::new(framenum)) as *const c_void
            }
            Some(FieldConvert::Protocol(protocol)) => *protocol as *const c_void,
            Some(FieldConvert::RangeStrings(range_strings)) => {
                let values: Vec<epan_sys::range_string> = range_strings
                    .iter()
                    .map(|range_string| range_string.into())
                    .chain(std::iter::once(epan_sys::range_string {
                        value_min: 0,
                        value_max: 0,
                        strptr: std::ptr::null(),
                    }))
                    .collect();
                Box::into_raw(values.into_boxed_slice()) as *const c_void
            }
            Some(FieldConvert::TrueFalseString(true_false_string)) => Box::into_raw(Box::new(
                epan_sys::true_false_string::from(true_false_string),
            ))
                as *const c_void,
            Some(FieldConvert::ValueStrings(value_strings)) => {
                let values: Vec<epan_sys::value_string> = value_strings
                    .iter()
                    .map(|value_string| value_string.into())
                    .chain(std::iter::once(epan_sys::value_string {
                        value: 0,
                        strptr: std::ptr::null(),
                    }))
                    .collect();
                Box::into_raw(values.into_boxed_slice()) as *const c_void
            }
            Some(FieldConvert::Val64Strings(val64_strings)) => {
                let values: Vec<epan_sys::val64_string> = val64_strings
                    .iter()
                    .map(|val64_string| val64_string.into())
                    .chain(std::iter::once(epan_sys::val64_string {
                        value: 0,
                        strptr: std::ptr::null(),
                    }))
                    .collect();
                Box::into_raw(values.into_boxed_slice()) as *const c_void
            }
            None => std::ptr::null(),
        };

        let hf_info = epan_sys::hf_register_info {
            p_id: &mut handle,
            hfinfo: epan_sys::header_field_info {
                name: to_c_str(&field.name),
                abbrev: to_c_str(&field.abbrev),
                type_: field.field_type.to_u32(),
                display: field.display.to_u32() as i32,
                strings: strings_ptr,
                bitmask: field.bitmask,
                blurb: field
                    .blurb
                    .as_ref()
                    .map_or(std::ptr::null(), |s| to_c_str(s)),
                id: -1,
                parent: 0,
                ref_type: epan_sys::hf_ref_type_HF_REF_TYPE_NONE,
                same_name_prev_id: -1,
                same_name_next: std::ptr::null_mut(),
            },
        };

        let hf_ptr: *mut epan_sys::hf_register_info = Box::into_raw(Box::new(hf_info)); // Header fields need to persist and wireshark takes ownership
        debug_assert!(handle == -1);
        epan_sys::proto_register_field_array(self.get_proto_handle(), hf_ptr, 1);

        if handle != -1 {
            self.field_handles
                .insert(field.id.clone(), FieldHandle { handle });

            // Don't free on success -> wireshark took ownership
            Ok(())
        } else {
            let _ = Box::from_raw(hf_ptr); // Clean up
            Err(RegistrationError::RegistrationFailed)
        }
    }
    pub(crate) fn get_ett_handle(&self, id: &str) -> Option<c_int> {
        Some(self.ett_handles.get(id)?.handle)
    }
    // This should be called by the Protocol.register routine unless you know what you're doing
    unsafe fn register_ett(&mut self) {
        // Initialize ett handles with -1
        let mut ett_handles = vec![-1; self.ett_defs.len()];

        // Create array of pointers to ett handles
        let ett_ptrs: Vec<*mut c_int> = ett_handles.iter_mut().map(|h| h as *mut c_int).collect();

        // Register the ETT array with Wireshark
        epan_sys::proto_register_subtree_array(ett_ptrs.as_ptr(), ett_handles.len() as c_int);

        // Store handles mapped to their IDs
        for (i, ett) in self.ett_defs.iter().enumerate() {
            self.ett_handles.insert(
                ett.id.clone(),
                EttHandle {
                    handle: ett_handles[i],
                },
            );
        }
    }

    // Get the handle to the protocol's ETT
    pub(crate) fn get_proto_handle(&self) -> c_int {
        self.proto_handle
    }
    // Get the handle to a field that has already been registered
    pub(crate) fn get_field_handle(&self, abbrev: &str) -> Option<&FieldHandle> {
        self.field_handles.get(abbrev)
    }

    pub(crate) fn get_fragment_items(&'_ self) -> Option<FragmentItemsOwned<'_>> {
        self.fragment_items.as_ref().and_then(|fragment_items| {
            Some(FragmentItemsOwned {
                ett_fragment: self.get_ett_handle(&fragment_items.ett_fragment)?,

                ett_fragments: fragment_items
                    .ett_fragments
                    .as_ref()
                    .and_then(|ett_fragments| self.get_ett_handle(ett_fragments)),

                hf_fragments: self.get_field_handle(&fragment_items.hf_fragments)?.handle,

                hf_fragment: self.get_field_handle(&fragment_items.hf_fragment)?.handle,

                hf_fragment_overlap: self
                    .get_field_handle(&fragment_items.hf_fragment_overlap)?
                    .handle,

                hf_fragment_overlap_conflict: self
                    .get_field_handle(&fragment_items.hf_fragment_overlap_conflict)?
                    .handle,

                hf_fragment_multiple_tails: self
                    .get_field_handle(&fragment_items.hf_fragment_multiple_tails)?
                    .handle,

                hf_fragment_too_long_fragment: self
                    .get_field_handle(&fragment_items.hf_fragment_too_long_fragment)?
                    .handle,

                hf_fragment_error: self
                    .get_field_handle(&fragment_items.hf_fragment_error)?
                    .handle,

                hf_fragment_count: fragment_items
                    .hf_fragment_count
                    .as_ref()
                    .and_then(|value| Some(self.get_field_handle(value)?.handle)),

                hf_reassembled_in: fragment_items
                    .hf_reassembled_in
                    .as_ref()
                    .and_then(|value| Some(self.get_field_handle(value)?.handle)),

                hf_reassembled_length: fragment_items
                    .hf_reassembled_length
                    .as_ref()
                    .and_then(|value| Some(self.get_field_handle(value)?.handle)),

                hf_reassembled_data: fragment_items
                    .hf_reassembled_data
                    .as_ref()
                    .and_then(|value| Some(self.get_field_handle(value)?.handle)),

                tag: &fragment_items.tag,
            })
        })
    }

    unsafe fn register_expert_info(
        &mut self,
        expert_module: *mut epan_sys::expert_module_t,
        info: &ExpertFieldInfo,
    ) -> Result<(), RegistrationError> {
        let expert_field: epan_sys::expert_field = epan_sys::expert_field { ei: -1, hf: -1 };
        let expert_field_ptr = Box::into_raw(Box::new(expert_field));

        // These resources just need to be alive for the registration
        let name = to_c_str(&format!("{}.{}", self.filter, info.id));
        let summary = to_c_str(&info.summary);

        let ei_info = epan_sys::ei_register_info {
            ids: expert_field_ptr,
            eiinfo: epan_sys::expert_field_info {
                name,
                group: info.group.to_u32() as i32,
                severity: info.severity.to_u32() as i32,
                summary,
                id: 0,
                protocol: std::ptr::null(),
                orig_severity: 0,
                hf_info: epan_sys::hf_register_info {
                    p_id: std::ptr::null_mut(), // overwrite with address of expert_field's hf
                    hfinfo: epan_sys::header_field_info {
                        name: std::ptr::null_mut(),
                        abbrev: std::ptr::null_mut(),
                        type_: epan_sys::ftenum_FT_NONE,
                        display: epan_sys::field_display_e_BASE_NONE as i32,
                        strings: std::ptr::null(),
                        bitmask: 0,
                        blurb: std::ptr::null(),
                        id: -1,
                        parent: 0,
                        ref_type: epan_sys::hf_ref_type_HF_REF_TYPE_NONE,
                        same_name_prev_id: -1,
                        same_name_next: std::ptr::null_mut(),
                    },
                },
            },
        };

        let ei_ptr = Box::into_raw(Box::new(ei_info));

        epan_sys::expert_register_field_array(expert_module, ei_ptr, 1);

        if (*(*ei_ptr).ids).ei != -1 && (*(*ei_ptr).ids).hf != -1 {
            self.expert_module.expert_fields_handles.insert(
                info.id.clone(),
                ExpertFieldHandle {
                    ei: (*(*ei_ptr).ids).ei,
                    hf: (*(*ei_ptr).ids).hf,
                },
            );
            Ok(())
        } else {
            let _ = Box::from_raw(expert_field_ptr);
            let _ = Box::from_raw(ei_ptr);
            Err(RegistrationError::RegistrationFailed)
        }
    }
    pub(crate) fn get_expert_field(&self, id: &str) -> Option<&ExpertFieldHandle> {
        self.expert_module.expert_fields_handles.get(id)
    }
    // Routine to be called from the proto_plugin.register_protoinfo in plugin registration
    pub(crate) fn register(&mut self) {
        let fields_to_register = self.field_defs.clone();
        let expert_infos_to_register = self.expert_module.expert_info_defs.clone();

        unsafe {
            for field in fields_to_register {
                self.register_field(&field)
                    .expect("Failed to register field");
            }
            // Registering ETT is basically saying how many types of trees you have
            self.register_ett();

            // Registering Expert Info and just retaining the expert field handles
            if !expert_infos_to_register.is_empty() {
                let expert_module = epan_sys::expert_register_protocol(self.proto_handle);
                self.expert_module.ptr = expert_module;
                for expert_info in expert_infos_to_register {
                    self.register_expert_info(expert_module, &expert_info)
                        .expect("Failed to register expert info");
                }
            }
        }
    }

    pub(crate) unsafe extern "C" fn dispatch_to_dissector(
        &self,
        tvb: *mut epan_sys::tvbuff,
        pinfo: *mut epan_sys::_packet_info,
        tree: *mut epan_sys::proto_tree,
    ) -> c_int {
        (self.dissector_fn).process_packet(tvb, pinfo, tree, self)
    }

    pub(crate) unsafe extern "C" fn dissector_handler(
        tvb: *mut epan_sys::tvbuff,
        pinfo: *mut epan_sys::_packet_info,
        tree: *mut epan_sys::proto_tree,
        _data: *mut c_void,
    ) -> c_int {
        let curr_proto = (*pinfo).current_proto;

        // Here we can always retrieve the name of protocol from pinfo
        let id = match std::ffi::CStr::from_ptr(curr_proto).to_str() {
            Ok(id) => id,
            Err(_) => return 0, // This shouldn't happen as long as the protocols are registered correctly in wsdf's macros
        };
        let result = Plugin::with(|plugin| {
            if let Some(protocol) = plugin.get_protocol(id) {
                let protocol = protocol.borrow();
                protocol.dispatch_to_dissector(tvb, pinfo, tree)
            } else {
                // Shouldn't reach here either
                0
            }
        });

        result
    }
}

pub struct FieldBuilder {
    id: String,
    name: String,
    abbrev: String,
    field_type: Option<FieldType>,
    display: Option<FieldDisplay>,
    strings: Option<FieldConvert>,
    bitmask: u64,
    blurb: Option<String>,
}
impl FieldBuilder {
    pub fn new(id: impl Into<String>, name: impl Into<String>, abbrev: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            abbrev: abbrev.into(),
            field_type: None,
            display: None,
            strings: None,
            bitmask: 0,
            blurb: None,
        }
    }

    pub fn field_type(mut self, field_type: FieldType) -> Self {
        self.field_type = Some(field_type);
        self
    }

    pub fn display(mut self, display: FieldDisplay) -> Self {
        self.display = Some(display);
        self
    }

    pub fn strings(mut self, strings: FieldConvert) -> Self {
        self.strings = Some(strings);
        self
    }

    pub fn bitmask(mut self, bitmask: u64) -> Self {
        self.bitmask = bitmask;
        self
    }

    pub fn blurb(mut self, blurb: impl Into<String>) -> Self {
        self.blurb = Some(blurb.into());
        self
    }

    pub fn build(self) -> Result<Field, RegistrationError> {
        Ok(Field {
            id: self.id,
            name: self.name,
            abbrev: self.abbrev,
            field_type: self.field_type.ok_or(RegistrationError::MissingFieldType)?,
            display: self.display.unwrap_or_default(),
            strings: self.strings,
            bitmask: self.bitmask,
            blurb: self.blurb,
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct FieldHandle {
    pub(crate) handle: c_int,
}

#[derive(Clone, Debug)]
pub(crate) struct Ett {
    id: String,
    _name: String,
}

#[derive(Clone, Debug)]
pub(crate) struct EttHandle {
    handle: c_int,
}

pub const ROOT_ETT_ID: &str = "_root";

pub(crate) struct ExpertModule {
    expert_info_defs: Vec<ExpertFieldInfo>,
    // Lookup for expert field handles
    expert_fields_handles: HashMap<String, ExpertFieldHandle>,
    // Inner ptr to expert field modules
    ptr: *mut epan_sys::expert_module_t,
}

pub(crate) struct ExpertFieldHandle {
    pub(crate) ei: c_int,
    pub(crate) hf: c_int,
}

#[derive(Clone)]
struct ExpertFieldInfo {
    id: String,
    group: ExpertGroup,
    severity: ExpertSeverity,
    summary: String,
}

pub struct ProtocolBuilder {
    name: String,
    abbrev: String,
    filter: String,
    dissector_fn: Option<Dissector>,
    fields: Vec<Field>,
    ett: Vec<Ett>,
    expert_infos: Vec<ExpertFieldInfo>,
    match_definitions: Vec<DissectorDecodeFrom>,
    fragment_items: Option<FragmentItemsNames>,
}

impl ProtocolBuilder {
    pub fn new(
        name: impl Into<String>,
        abbrev: impl Into<String>,
        filter: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            abbrev: abbrev.into(),
            filter: filter.into(),
            dissector_fn: None,
            fields: Vec::new(),
            ett: Vec::new(),
            expert_infos: Vec::new(),
            match_definitions: Vec::new(),
            fragment_items: None,
        }
    }

    pub fn dissector(mut self, dissector: Dissector) -> Self {
        self.dissector_fn = Some(dissector);
        self
    }

    pub fn field(mut self, field: Field) -> Self {
        self.fields.push(field);
        self
    }

    pub fn ett(mut self, id: impl Into<String>, name: impl Into<String>) -> Self {
        self.ett.push(Ett {
            id: id.into(),
            _name: name.into(),
        });
        self
    }

    pub fn fragment_items(mut self, fragment_items: FragmentItemsNames) -> Self {
        self.fragment_items = Some(fragment_items);
        self
    }

    pub fn expert_info(
        mut self,
        id: impl Into<String>,
        group: ExpertGroup,
        severity: ExpertSeverity,
        summary: impl Into<String>,
    ) -> Self {
        self.expert_infos.push(ExpertFieldInfo {
            id: id.into(),
            group,
            severity,
            summary: summary.into(),
        });
        self
    }

    pub fn decode_from(mut self, decode_from: DissectorDecodeFrom) -> Self {
        self.match_definitions.push(decode_from);
        self
    }

    pub fn build(self) -> Result<Protocol, RegistrationError> {
        let dissector = self
            .dissector_fn
            .ok_or(RegistrationError::MissingDissector)?;

        unsafe {
            let proto_handle = epan_sys::proto_register_protocol(
                to_c_str(&self.name),
                to_c_str(&self.abbrev),
                to_c_str(&self.filter),
            );
            debug_assert!(proto_handle != -1);

            // Ett def list should include root ETT type
            let mut ett_defs = vec![Ett {
                id: ROOT_ETT_ID.to_string(),
                _name: format!("{} Protocol Tree", self.name),
            }];
            ett_defs.extend(self.ett);

            Ok(Protocol {
                _name: self.name,
                abbrev: self.abbrev,
                filter: self.filter,
                proto_handle,
                ett_defs,
                ett_handles: HashMap::new(),
                dissector_fn: dissector,
                field_defs: self.fields,       // Store the field definitions
                field_handles: HashMap::new(), // Will be populated during registration
                expert_module: ExpertModule {
                    expert_info_defs: self.expert_infos,
                    expert_fields_handles: HashMap::new(),
                    ptr: std::ptr::null_mut(), // Will be populated during registration
                },
                match_definitions: Some(self.match_definitions),
                fragment_items: self.fragment_items,
            })
        }
    }
}

#[derive(Clone)]
pub struct Field {
    pub id: String,
    pub name: String,
    pub abbrev: String,
    pub field_type: FieldType,
    pub display: FieldDisplay,
    /// Additional data used to customize the description of a field's value
    ///
    /// If not provided, the default for the given [`FieldType`] and [`FieldDisplay`] will be used.
    pub strings: Option<FieldConvert>,
    pub bitmask: u64,
    pub blurb: Option<String>,
}

/// Wrapper around `epan_sys::fragment_items`.
///
/// Uses `PhantomData` to bounds the lifetimes of the raw pointers inside `epan_sys::fragment_items`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct FragmentItems<'a> {
    inner: epan_sys::fragment_items,
    phantom: PhantomData<&'a epan_sys::fragment_items>,
}

impl<'a> FragmentItems<'a> {
    fn new(fragment_items: epan_sys::fragment_items) -> Self {
        Self {
            inner: fragment_items,
            phantom: PhantomData,
        }
    }

    pub(crate) fn as_ptr(&mut self) -> *mut epan_sys::fragment_items {
        std::ptr::from_mut(&mut self.inner)
    }
}

#[derive(Debug, Default)]
pub struct FragmentItemsNames {
    pub ett_fragment: String,
    pub ett_fragments: Option<String>,
    pub hf_fragments: String,
    pub hf_fragment: String,
    pub hf_fragment_overlap: String,
    pub hf_fragment_overlap_conflict: String,
    pub hf_fragment_multiple_tails: String,
    pub hf_fragment_too_long_fragment: String,
    pub hf_fragment_error: String,
    pub hf_fragment_count: Option<String>,
    pub hf_reassembled_in: Option<String>,
    pub hf_reassembled_length: Option<String>,
    pub hf_reassembled_data: Option<String>,
    pub tag: String,
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct FragmentItemsOwned<'a> {
    ett_fragment: c_int,
    ett_fragments: Option<c_int>,
    hf_fragments: c_int,
    hf_fragment: c_int,
    hf_fragment_overlap: c_int,
    hf_fragment_overlap_conflict: c_int,
    hf_fragment_multiple_tails: c_int,
    hf_fragment_too_long_fragment: c_int,
    hf_fragment_error: c_int,
    hf_fragment_count: Option<c_int>,
    hf_reassembled_in: Option<c_int>,
    hf_reassembled_length: Option<c_int>,
    hf_reassembled_data: Option<c_int>,
    tag: &'a str,
}

impl<'a> From<&'a mut FragmentItemsOwned<'a>> for FragmentItems<'a> {
    fn from(intermediate: &'a mut FragmentItemsOwned) -> Self {
        FragmentItems::new(epan_sys::fragment_items {
            ett_fragment: std::ptr::from_mut(&mut intermediate.ett_fragment),
            ett_fragments: intermediate
                .ett_fragments
                .as_mut()
                .map(std::ptr::from_mut)
                .unwrap_or(std::ptr::null_mut()),
            hf_fragments: std::ptr::from_mut(&mut intermediate.hf_fragments),
            hf_fragment: std::ptr::from_mut(&mut intermediate.hf_fragment),
            hf_fragment_overlap: std::ptr::from_mut(&mut intermediate.hf_fragment_overlap),
            hf_fragment_overlap_conflict: std::ptr::from_mut(
                &mut intermediate.hf_fragment_overlap_conflict,
            ),
            hf_fragment_multiple_tails: std::ptr::from_mut(
                &mut intermediate.hf_fragment_multiple_tails,
            ),
            hf_fragment_too_long_fragment: std::ptr::from_mut(
                &mut intermediate.hf_fragment_too_long_fragment,
            ),
            hf_fragment_error: std::ptr::from_mut(&mut intermediate.hf_fragment_error),
            hf_fragment_count: intermediate
                .hf_fragment_count
                .as_mut()
                .map(std::ptr::from_mut)
                .unwrap_or(std::ptr::null_mut()),
            hf_reassembled_in: intermediate
                .hf_reassembled_in
                .as_mut()
                .map(std::ptr::from_mut)
                .unwrap_or(std::ptr::null_mut()),
            hf_reassembled_length: intermediate
                .hf_reassembled_length
                .as_mut()
                .map(std::ptr::from_mut)
                .unwrap_or(std::ptr::null_mut()),
            hf_reassembled_data: intermediate
                .hf_reassembled_data
                .as_mut()
                .map(std::ptr::from_mut)
                .unwrap_or(std::ptr::null_mut()),
            tag: to_c_str(intermediate.tag),
        })
    }
}
