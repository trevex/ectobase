// Unprivileged rte_flow binding smoke: prove the binding + safe wrapper construct FFI structs
// soundly and route the PMD's error through `FlowError` WITHOUT panicking. The net_null PMD has no
// rte_flow support, so `validate` must return `Err(FlowError)` (typically -ENOTSUP). Also asserts
// the offload decision defaults to `Software` on a non-mlx5 driver. --test-threads=1.
use nfkit::{
    flow_validate, ingress_attr, offload_mode, Backend, Eal, Match5Drop, Mempool, OffloadMode, Port,
};

#[test]
fn flow_binding_validate_errors_gracefully_on_null_pmd() {
    // Build the EAL argv from the Null backend, plus a unique file-prefix (each test binary is its
    // own process; EAL is process-global and inits at most once).
    let mut args = Backend::Null.eal_args("nfkit-flow-binding");
    args.push("--file-prefix".into());
    args.push("nfkit_flow_binding".into());
    let _eal = Eal::init(args).expect("EAL init");

    let pool = Mempool::new("flow_binding_pool", 1023, 250, 0).expect("pool");
    let _port = Port::configure(0, 1, &pool).expect("configure port 0");

    // Build a 5-tuple→DROP rule holder + the ingress attr; bind both to a `let` so their
    // spec/mask/attr outlive the validate call (the wrapper passes raw pointers into them).
    let attr = ingress_attr();
    let rule = Match5Drop::new([10, 0, 0, 1], 8080);

    // net_null has no flow support → expect Err, NOT a panic. This exercises the whole path:
    // struct construction, the FFI call, and reading rte_flow_error.message into a String.
    let result = flow_validate(0, &attr, rule.items(), rule.actions());
    match result {
        Ok(()) => panic!("net_null unexpectedly accepted a flow rule"),
        Err(e) => {
            // Prove the error carried through without UB: fields are readable + Display works.
            eprintln!(
                "flow_validate on net_null returned Err as expected: type={} errno={} message={:?}",
                e.etype, e.errno, e.message
            );
            eprintln!("Display: {e}");
        }
    }

    // Non-mlx5 driver → the datapath's decision must be the software fallback.
    assert_eq!(
        offload_mode(0),
        OffloadMode::Software,
        "net_null is not mlx5 → Software fallback"
    );
}
