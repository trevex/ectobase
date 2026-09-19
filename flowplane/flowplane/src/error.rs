//! Typed error boundary for the dataplane gRPC service.
//!
//! The attach/control handlers produce failures in four semantic classes; carrying them as a typed
//! enum (rather than a stringly-typed `anyhow::Error` mapped to `Status::internal`) lets `node.rs`
//! map each to the correct gRPC `Status` code. That matters for the CNI: a `Conflict` (an IP already
//! in use) must surface as `AlreadyExists` so the client does NOT auto-retry it as a transient
//! `Internal` fault. Any error that is not one of the explicit client classes flows through the
//! `#[from] anyhow::Error` blanket into `Internal`, so `?` on an `anyhow::Result` keeps working.
#[derive(thiserror::Error, Debug)]
pub enum ServiceError {
    /// A client conflict: the requested resource is already held by a different endpoint (e.g. an
    /// overlay IP in use in the VNI). Maps to `AlreadyExists` — clients must NOT auto-retry.
    #[error("{0}")]
    Conflict(String),
    /// The referenced resource does not exist (e.g. no local interface for a NAT source). Maps to
    /// `NotFound`.
    #[error("{0}")]
    NotFound(String),
    /// The request is malformed or semantically invalid (bad/missing argument). Maps to
    /// `InvalidArgument`.
    #[error("{0}")]
    Invalid(String),
    /// The request exceeds a fixed dataplane budget (e.g. an interface's firewall rule slots). Maps
    /// to `ResourceExhausted` — retrying the same request cannot succeed.
    #[error("{0}")]
    Exhausted(String),
    /// A genuine internal/server fault (shell-out failure, map programming error, …). Maps to
    /// `Internal`, which gRPC clients may retry.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl From<ServiceError> for tonic::Status {
    fn from(e: ServiceError) -> Self {
        match e {
            ServiceError::Conflict(m) => tonic::Status::already_exists(m),
            ServiceError::NotFound(m) => tonic::Status::not_found(m),
            ServiceError::Invalid(m) => tonic::Status::invalid_argument(m),
            ServiceError::Exhausted(m) => tonic::Status::resource_exhausted(m),
            // `{:#}` renders the full anyhow context chain (e.g. the underlying `ip netns exec` /
            // `ip tuntap` stderr), not just the top `.context(...)` line.
            ServiceError::Internal(e) => tonic::Status::internal(format!("{e:#}")),
        }
    }
}

impl From<flowplane_control::FwError> for ServiceError {
    fn from(e: flowplane_control::FwError) -> Self {
        use flowplane_control::FwError;
        match e {
            FwError::UnknownInterface => ServiceError::NotFound(e.to_string()),
            FwError::ScopeTooLarge { .. } => ServiceError::Exhausted(e.to_string()),
            FwError::Unsupported(_) => ServiceError::Invalid(e.to_string()),
            FwError::Map(e) => ServiceError::Internal(e),
        }
    }
}

impl From<flowplane_control::NeighborNatError> for ServiceError {
    fn from(e: flowplane_control::NeighborNatError) -> Self {
        use flowplane_control::NeighborNatError;
        match e {
            NeighborNatError::EmptyRange => ServiceError::Invalid(e.to_string()),
            NeighborNatError::Overlap => ServiceError::Conflict(e.to_string()),
            NeighborNatError::Full { .. } => ServiceError::Exhausted(e.to_string()),
            NeighborNatError::Map(e) => ServiceError::Internal(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_map_to_expected_status_codes() {
        assert_eq!(
            tonic::Status::from(ServiceError::Conflict("x".into())).code(),
            tonic::Code::AlreadyExists
        );
        assert_eq!(
            tonic::Status::from(ServiceError::NotFound("x".into())).code(),
            tonic::Code::NotFound
        );
        assert_eq!(
            tonic::Status::from(ServiceError::Invalid("x".into())).code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            tonic::Status::from(ServiceError::Exhausted("x".into())).code(),
            tonic::Code::ResourceExhausted
        );
        assert_eq!(
            tonic::Status::from(ServiceError::Internal(anyhow::anyhow!("x"))).code(),
            tonic::Code::Internal
        );
    }

    #[test]
    fn neighbor_nat_errors_map_to_expected_status_codes() {
        use flowplane_control::NeighborNatError;
        let code = |e: NeighborNatError| tonic::Status::from(ServiceError::from(e)).code();
        assert_eq!(
            code(NeighborNatError::EmptyRange),
            tonic::Code::InvalidArgument
        );
        assert_eq!(code(NeighborNatError::Overlap), tonic::Code::AlreadyExists);
        assert_eq!(
            code(NeighborNatError::Full {
                needed: 30,
                max: 65536
            }),
            tonic::Code::ResourceExhausted
        );
        assert_eq!(
            code(NeighborNatError::Map(anyhow::anyhow!("x"))),
            tonic::Code::Internal
        );
    }

    #[test]
    fn conflict_preserves_message_text() {
        // The CNI/e2e greps for the "ROUTE_EXISTS:" prefix; it must ride through under AlreadyExists.
        let s = tonic::Status::from(ServiceError::Conflict(
            "ROUTE_EXISTS: IP already in use in this VNI".into(),
        ));
        assert_eq!(s.code(), tonic::Code::AlreadyExists);
        assert_eq!(s.message(), "ROUTE_EXISTS: IP already in use in this VNI");
    }

    #[test]
    fn anyhow_error_converts_via_from() {
        // `?` on an anyhow::Result in a `Result<_, ServiceError>` fn relies on this blanket From.
        let e: ServiceError = anyhow::anyhow!("boom").into();
        assert!(matches!(e, ServiceError::Internal(_)));
    }
}
