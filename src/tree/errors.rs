use thiserror::Error;
use tonic::Status;

#[derive(Error, Debug)]
pub enum KtError {
    #[error("Requested version of the label has expired")]
    Expired,

    #[error("Requested version of the label is unavailable")]
    Unavailable,

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("greatest_version does not match the current greatest version of the label")]
    VersionConflict,
}

impl From<KtError> for Status {
    fn from(e: KtError) -> Self {
        match e {
            KtError::Expired => Status::not_found("Requested version of the label has expired"),
            KtError::Unavailable => {
                Status::not_found("Requested version of the label is unavailable")
            }
            KtError::Internal(msg) => Status::internal(msg),
            KtError::InvalidArgument(msg) => Status::invalid_argument(msg),
            KtError::VersionConflict => Status::failed_precondition(
                "greatest_version does not match the current greatest version of the label",
            ),
        }
    }
}

// Helper to map anyhow::Error to Status via KtError if applicable, or generic internal
pub fn map_anyhow_to_status(e: anyhow::Error) -> Status {
    // Check if the root cause is a KtError
    if let Some(kte) = e.downcast_ref::<KtError>() {
        // We have to match again because downcast_ref gives reference
        match kte {
            KtError::Expired => Status::not_found("Requested version of the label has expired"),
            KtError::Unavailable => {
                Status::not_found("Requested version of the label is unavailable")
            }
            KtError::Internal(msg) => Status::internal(msg.clone()),
            KtError::InvalidArgument(msg) => Status::invalid_argument(msg.clone()),
            KtError::VersionConflict => Status::failed_precondition(
                "greatest_version does not match the current greatest version of the label",
            ),
        }
    } else {
        // Fallback for generic errors
        Status::internal(e.to_string())
    }
}
