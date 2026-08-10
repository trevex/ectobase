//! Safe rte_flow wrapper: validate/create/destroy flow rules + a runtime probe for mlx5 RAW
//! decap/encap offload. Rules are END-terminated item/action arrays; the spec/mask structs they
//! reference are owned by a builder holder (`Match5Drop`/`RawDecap`/`RawEncap`) that the caller
//! binds to a `let` so it outlives the `validate`/`create` call (rte_flow copies spec/mask during
//! the call, but the pointers must be valid for its duration). Modelled on `dpdk_hash.rs`
//! (RAII `Drop`, `!Send`, `// SAFETY:` on every `unsafe`).
use dpdk_sys as ffi;
use std::marker::PhantomData;
use std::os::raw::c_void;

/// A failed `validate`/`create`: the DPDK `rte_flow_error.type_`, the negative return code (an
/// errno, e.g. `-ENOTSUP`), and the human-readable `rte_flow_error.message` (may be empty).
#[derive(Debug)]
pub struct FlowError {
    pub etype: u32,
    pub errno: i32,
    pub message: String,
}

impl std::fmt::Display for FlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "rte_flow error (type={}, errno={}): {}",
            self.etype, self.errno, self.message
        )
    }
}

impl std::error::Error for FlowError {}

/// Read a zeroed-then-populated `rte_flow_error` into a `FlowError`, guarding the (possibly null)
/// `message` C string. `rc` is the negative return code (0 for the create-null case where only the
/// error struct carries info).
fn read_error(err: &ffi::rte_flow_error, rc: i32) -> FlowError {
    // SAFETY: `err.message` is either null or a NUL-terminated C string owned by the PMD and valid
    // for the duration of this call (we copy it into an owned String immediately). We guard null.
    let message = if err.message.is_null() {
        String::new()
    } else {
        unsafe { std::ffi::CStr::from_ptr(err.message) }
            .to_string_lossy()
            .into_owned()
    };
    FlowError {
        etype: err.type_,
        errno: rc,
        message,
    }
}

/// RAII flow rule — programmed on the wire until dropped, then `rte_flow_destroy`d. `!Send`: a
/// rule is bound to the port's lcore (rte_flow fast-path calls are lcore-affine).
pub struct FlowRule {
    port: u16,
    ptr: *mut ffi::rte_flow,
    _not_send: PhantomData<*const ()>,
}

impl Drop for FlowRule {
    fn drop(&mut self) {
        let mut err: ffi::rte_flow_error = unsafe { std::mem::zeroed() };
        // SAFETY: `self.ptr` is a live rule handle returned by `rte_flow_create` on `self.port`
        // (never null — `create` maps null to `Err`). This is the sole owner, so destroy runs
        // exactly once. `&mut err` is a valid out-param the call may write.
        unsafe {
            ffi::rte_flow_destroy(self.port, self.ptr, &mut err);
        }
    }
}

/// Validate a rule against the PMD without programming it. `Ok(())` means the PMD accepts the
/// rule. `pattern`/`actions` must be END-terminated (`Match5Drop`/`RawDecap`/`RawEncap` build them
/// so); their referenced spec/mask must outlive this call (owned by the holder).
///
/// # Errors
/// Returns `FlowError` (with the PMD's error type + message) if `rte_flow_validate` returns nonzero
/// (e.g. `-ENOTSUP` on a PMD without flow support).
pub fn validate(
    port: u16,
    attr: &ffi::rte_flow_attr,
    pattern: &[ffi::rte_flow_item],
    actions: &[ffi::rte_flow_action],
) -> Result<(), FlowError> {
    let mut err: ffi::rte_flow_error = unsafe { std::mem::zeroed() };
    // SAFETY: `attr`, `pattern`, `actions` are valid, END-terminated (caller invariant) arrays that
    // live for the call; their spec/mask are owned by the caller's holder and outlive the call.
    // `&mut err` is a valid out-param. rte_flow_validate only reads the inputs.
    let rc = unsafe {
        ffi::rte_flow_validate(
            port,
            attr as *const ffi::rte_flow_attr,
            pattern.as_ptr(),
            actions.as_ptr(),
            &mut err,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(read_error(&err, rc))
    }
}

/// Create (program) a rule; returns a RAII handle that destroys it on drop. Same array/lifetime
/// invariants as [`validate`].
///
/// # Errors
/// Returns `FlowError` if `rte_flow_create` returns null (the PMD's error type + message describe
/// why, e.g. unsupported).
pub fn create(
    port: u16,
    attr: &ffi::rte_flow_attr,
    pattern: &[ffi::rte_flow_item],
    actions: &[ffi::rte_flow_action],
) -> Result<FlowRule, FlowError> {
    let mut err: ffi::rte_flow_error = unsafe { std::mem::zeroed() };
    // SAFETY: identical invariants to `validate` — valid END-terminated arrays live for the call,
    // spec/mask outlive it (owned by the caller's holder), `&mut err` is a valid out-param.
    let ptr = unsafe {
        ffi::rte_flow_create(
            port,
            attr as *const ffi::rte_flow_attr,
            pattern.as_ptr(),
            actions.as_ptr(),
            &mut err,
        )
    };
    if ptr.is_null() {
        // create sets rte_errno + the error struct; there is no rc, so report errno=0.
        Err(read_error(&err, 0))
    } else {
        Ok(FlowRule {
            port,
            ptr,
            _not_send: PhantomData,
        })
    }
}

/// An ingress attribute at group 0, priority 0 (`ingress=1`). Zero-initialized then the `ingress`
/// bitfield is set via bindgen's `set_ingress`.
#[must_use]
pub fn ingress_attr() -> ffi::rte_flow_attr {
    // SAFETY: rte_flow_attr is a POD C struct; an all-zero bit pattern is a valid instance
    // (group=0, priority=0, all direction bits clear). `set_ingress` then flips one bit.
    let mut attr: ffi::rte_flow_attr = unsafe { std::mem::zeroed() };
    attr.set_ingress(1);
    attr
}

/// Holder for a 5-tuple-match → DROP rule. Owns the ipv4/tcp spec+mask structs and the
/// END-terminated `items`/`actions` arrays so they all outlive a `validate`/`create` call. The
/// `spec`/`mask` pointers stored in `items` point INTO this struct, so it must not be moved after
/// construction while those pointers are in flight — callers bind it to a `let` and pass
/// `.items()`/`.actions()` by reference; the arrays are rebuilt lazily-free because the pointers are
/// captured at `new()` time relative to boxed storage.
pub struct Match5Drop {
    // Boxed so the spec/mask have a stable address independent of where the holder itself lives
    // (the `items` array stores raw pointers into these). Held purely to keep that memory alive —
    // read only through the raw pointers in `items`, which the compiler can't see.
    #[allow(dead_code)]
    ipv4_spec: Box<ffi::rte_flow_item_ipv4>,
    #[allow(dead_code)]
    ipv4_mask: Box<ffi::rte_flow_item_ipv4>,
    #[allow(dead_code)]
    tcp_spec: Box<ffi::rte_flow_item_tcp>,
    #[allow(dead_code)]
    tcp_mask: Box<ffi::rte_flow_item_tcp>,
    items: [ffi::rte_flow_item; 4],
    actions: [ffi::rte_flow_action; 2],
}

impl Match5Drop {
    /// Build a rule matching IPv4 `dst_ip` (exact) + TCP `dst_port` (exact) → DROP. `dst_ip` is in
    /// network order [a,b,c,d]; `dst_port` is host order (converted to big-endian for the match).
    #[must_use]
    pub fn new(dst_ip: [u8; 4], dst_port: u16) -> Self {
        // SAFETY: rte_flow_item_ipv4/tcp are POD C structs wrapping a header; all-zero is valid
        // (zero = "don't care" once combined with the mask). We then set only dst fields + masks.
        let mut ipv4_spec: Box<ffi::rte_flow_item_ipv4> = Box::new(unsafe { std::mem::zeroed() });
        let mut ipv4_mask: Box<ffi::rte_flow_item_ipv4> = Box::new(unsafe { std::mem::zeroed() });
        let mut tcp_spec: Box<ffi::rte_flow_item_tcp> = Box::new(unsafe { std::mem::zeroed() });
        let mut tcp_mask: Box<ffi::rte_flow_item_tcp> = Box::new(unsafe { std::mem::zeroed() });

        // dst_addr is rte_be32_t (network byte order). `from_ne_bytes` stores the octets [a,b,c,d]
        // directly into memory = network order on any host. (from_be_bytes byte-reverses on LE —
        // net_tap's tc-flower filter then showed 9.0.0.10 for 10.0.0.9; caught by the e2e.)
        ipv4_spec.hdr.dst_addr = u32::from_ne_bytes(dst_ip);
        ipv4_mask.hdr.dst_addr = u32::from_ne_bytes([0xff, 0xff, 0xff, 0xff]);

        // dst_port is rte_be16_t (u16, network byte order).
        tcp_spec.hdr.dst_port = dst_port.to_be();
        tcp_mask.hdr.dst_port = 0xffff;

        // SAFETY: rte_flow_item is a POD struct of an enum tag + three raw pointers; all-zero is a
        // valid ETH item (spec/last/mask null = match any ETH). We then fill the IPV4/TCP/END slots.
        let mut items: [ffi::rte_flow_item; 4] = unsafe { std::mem::zeroed() };
        items[0].type_ = ffi::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_ETH;
        items[1].type_ = ffi::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_IPV4;
        items[1].spec = (&*ipv4_spec as *const ffi::rte_flow_item_ipv4).cast::<c_void>();
        items[1].mask = (&*ipv4_mask as *const ffi::rte_flow_item_ipv4).cast::<c_void>();
        items[2].type_ = ffi::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_TCP;
        items[2].spec = (&*tcp_spec as *const ffi::rte_flow_item_tcp).cast::<c_void>();
        items[2].mask = (&*tcp_mask as *const ffi::rte_flow_item_tcp).cast::<c_void>();
        items[3].type_ = ffi::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_END;

        // SAFETY: rte_flow_action is a POD struct of an enum tag + a raw conf pointer; all-zero is a
        // valid instance. DROP takes no conf; END terminates.
        let mut actions: [ffi::rte_flow_action; 2] = unsafe { std::mem::zeroed() };
        actions[0].type_ = ffi::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_DROP;
        actions[1].type_ = ffi::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_END;

        Self {
            ipv4_spec,
            ipv4_mask,
            tcp_spec,
            tcp_mask,
            items,
            actions,
        }
    }

    #[must_use]
    pub fn items(&self) -> &[ffi::rte_flow_item] {
        &self.items
    }

    #[must_use]
    pub fn actions(&self) -> &[ffi::rte_flow_action] {
        &self.actions
    }
}

/// Holder for a RAW_DECAP action (strip `size` outer bytes) + END-terminated `actions`. mlx5-only;
/// used by the probe. Owns the `rte_flow_action_raw_decap` conf so it outlives the call.
pub struct RawDecap {
    // Held to keep the conf alive; read only through the raw `conf` pointer in `actions[0]`.
    #[allow(dead_code)]
    conf: Box<ffi::rte_flow_action_raw_decap>,
    actions: [ffi::rte_flow_action; 2],
    // The conf's `data` pointer (may be null for a pure length-strip) points into this buffer.
    // Boxed slice = address-stable storage held purely for liveness (underscore = read only through
    // the raw `conf.data` pointer, which the compiler can't see).
    #[allow(dead_code)]
    _data: Box<[u8]>,
}

impl RawDecap {
    /// Strip `len` outer bytes. No template data is supplied (length-only strip), which is the
    /// common IPIP/tunnel-decap shape; `data` stays null, `size = len`.
    #[must_use]
    pub fn new(len: usize) -> Self {
        // SAFETY: rte_flow_action_raw_decap is POD (a `*mut u8` + a `usize`); all-zero is valid
        // (null data). We set only `size`.
        let mut conf: Box<ffi::rte_flow_action_raw_decap> = Box::new(unsafe { std::mem::zeroed() });
        conf.size = len;

        // SAFETY: POD action array; all-zero valid. Fill RAW_DECAP + END; wire conf pointer.
        let mut actions: [ffi::rte_flow_action; 2] = unsafe { std::mem::zeroed() };
        actions[0].type_ = ffi::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_RAW_DECAP;
        actions[0].conf = (&*conf as *const ffi::rte_flow_action_raw_decap).cast::<c_void>();
        actions[1].type_ = ffi::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_END;

        Self {
            conf,
            actions,
            _data: Box::new([]),
        }
    }

    #[must_use]
    pub fn actions(&self) -> &[ffi::rte_flow_action] {
        &self.actions
    }
}

/// Holder for a RAW_ENCAP action (push `data`) + END-terminated `actions`. mlx5-only; used by the
/// probe. Owns the encap `data` buffer AND the `rte_flow_action_raw_encap` conf so both outlive the
/// call.
pub struct RawEncap {
    // Held to keep the conf alive; read only through the raw `conf` pointer in `actions[0]`.
    #[allow(dead_code)]
    conf: Box<ffi::rte_flow_action_raw_encap>,
    actions: [ffi::rte_flow_action; 2],
    // `conf.data` points into this owned buffer; keep it alive + at a stable address (underscore =
    // held only for liveness, read through the raw `conf.data` pointer the compiler can't see).
    #[allow(dead_code)]
    _data: Box<[u8]>,
}

impl RawEncap {
    /// Push `data` as the new outer header(s). `preserve` is left null (nothing preserved).
    #[must_use]
    pub fn new(data: &[u8]) -> Self {
        let mut buf: Box<[u8]> = data.to_vec().into_boxed_slice();
        let data_ptr = buf.as_mut_ptr();
        let size = buf.len();

        // SAFETY: rte_flow_action_raw_encap is POD (`*mut u8` data + `*mut u8` preserve + usize);
        // all-zero is valid. We set data (into our owned buffer) + size; preserve stays null.
        let mut conf: Box<ffi::rte_flow_action_raw_encap> = Box::new(unsafe { std::mem::zeroed() });
        conf.data = data_ptr;
        conf.size = size;

        // SAFETY: POD action array; all-zero valid. Fill RAW_ENCAP + END; wire conf pointer.
        let mut actions: [ffi::rte_flow_action; 2] = unsafe { std::mem::zeroed() };
        actions[0].type_ = ffi::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_RAW_ENCAP;
        actions[0].conf = (&*conf as *const ffi::rte_flow_action_raw_encap).cast::<c_void>();
        actions[1].type_ = ffi::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_END;

        Self {
            conf,
            actions,
            _data: buf,
        }
    }

    #[must_use]
    pub fn actions(&self) -> &[ffi::rte_flow_action] {
        &self.actions
    }
}

/// The datapath's per-port offload decision.
#[derive(Debug, PartialEq, Eq)]
pub enum OffloadMode {
    /// mlx5 RAW decap/encap offload is available and validated — program it in hardware.
    HwRawFlow,
    /// No hardware RAW offload — run the encap/decap in software.
    Software,
}

/// An ETH+IPV6 pattern (type-only, match-any) used purely to probe RAW decap/encap support.
struct EthIpv6Pattern {
    items: [ffi::rte_flow_item; 3],
}

impl EthIpv6Pattern {
    fn new() -> Self {
        // SAFETY: POD item array; all-zero valid (null spec/mask = match any). Set the type tags.
        let mut items: [ffi::rte_flow_item; 3] = unsafe { std::mem::zeroed() };
        items[0].type_ = ffi::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_ETH;
        items[1].type_ = ffi::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_IPV6;
        items[2].type_ = ffi::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_END;
        Self { items }
    }
}

/// Read a port's DPDK driver name (e.g. `"mlx5_pci"`, `"net_null"`) as a `String`, or `None` if
/// `rte_eth_dev_info_get` fails or the name is null.
fn driver_name(port: u16) -> Option<String> {
    // SAFETY: rte_eth_dev_info is POD; zeroed is a valid empty instance. `&mut info` is a valid
    // out-param the call fills.
    let mut info: ffi::rte_eth_dev_info = unsafe { std::mem::zeroed() };
    let rc = unsafe { ffi::rte_eth_dev_info_get(port, &mut info) };
    if rc != 0 || info.driver_name.is_null() {
        return None;
    }
    // SAFETY: on rc==0 `driver_name` is a NUL-terminated C string owned by the ethdev layer, valid
    // for the lifetime of the device; we copy it into an owned String immediately.
    let name = unsafe { std::ffi::CStr::from_ptr(info.driver_name) }
        .to_string_lossy()
        .into_owned();
    Some(name)
}

/// True only if the port's driver is mlx5 AND `rte_flow_validate` accepts BOTH a RAW_DECAP and a
/// RAW_ENCAP rule. The decisive gate is validation succeeding (never the name alone). Logs the
/// decision. Nothing is programmed.
#[must_use]
pub fn probe_raw_flow_offload(port: u16) -> bool {
    let name = driver_name(port).unwrap_or_default();
    if !name.contains("mlx5") {
        eprintln!("nfkit::flow: port {port} driver {name:?} is not mlx5 → software fallback");
        return false;
    }

    let attr = ingress_attr();
    let pattern = EthIpv6Pattern::new();

    // Strip a plausible outer IPv6-in-IPv6 header length; the concrete length is immaterial to the
    // support probe (the PMD rejects with ENOTSUP if RAW_DECAP is unsupported at all).
    let decap = RawDecap::new(40);
    if let Err(e) = validate(port, &attr, &pattern.items, decap.actions()) {
        eprintln!("nfkit::flow: port {port} (mlx5) RAW_DECAP validate failed: {e} → software");
        return false;
    }

    // A minimal encap template (40 bytes of an outer IPv6 header shape); content is immaterial to
    // the support probe.
    let encap = RawEncap::new(&[0u8; 40]);
    if let Err(e) = validate(port, &attr, &pattern.items, encap.actions()) {
        eprintln!("nfkit::flow: port {port} (mlx5) RAW_ENCAP validate failed: {e} → software");
        return false;
    }

    eprintln!("nfkit::flow: port {port} (mlx5) RAW_DECAP+RAW_ENCAP validated → hardware offload");
    true
}

/// The datapath's offload decision for a port: `HwRawFlow` iff [`probe_raw_flow_offload`] is true,
/// else `Software`.
#[must_use]
pub fn offload_mode(port: u16) -> OffloadMode {
    if probe_raw_flow_offload(port) {
        OffloadMode::HwRawFlow
    } else {
        OffloadMode::Software
    }
}
