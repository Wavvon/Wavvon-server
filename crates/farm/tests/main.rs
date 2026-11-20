//! The crate's integration tests, compiled as one binary: one link of the
//! whole crate instead of one per file. Each file is a module.

mod admin_flow;
mod common;
mod e2e_server_agent;
mod farm_auth_flow;
mod farm_hub_e2e;
mod hub_role_flow;
mod hubs_flow;
mod node_tls_flow;
mod serial_claim_flow;
mod serial_routing_flow;
mod slug_flow;
