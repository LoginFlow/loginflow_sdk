//! Authorization of a resource request by LoginFlow permissions: the product's permission
//! manifest, the verification of the presented access token (framework-agnostic) and the DPoP
//! replay cache. The Actix route table and gate that enforce it live in [`crate::actix`].

pub mod header;
pub mod manifest;
pub mod replay;
pub mod verifier;
