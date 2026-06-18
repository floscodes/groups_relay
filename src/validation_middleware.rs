use crate::groups::NON_GROUP_ALLOWED_KINDS;
use nostr_sdk::prelude::*;
use relay_builder::nostr_middleware::{InboundContext, NostrMiddleware};
use tracing::{debug, warn};

use crate::groups::{
    ADDRESSABLE_EVENT_KINDS, KIND_GROUP_ADD_USER_9000, KIND_GROUP_CREATE_9007,
    KIND_GROUP_CREATE_INVITE_9009, KIND_GROUP_DELETE_9008, KIND_GROUP_DELETE_EVENT_9005,
    KIND_GROUP_EDIT_METADATA_9002, KIND_GROUP_REMOVE_USER_9001, KIND_GROUP_SET_ROLES_9006,
    KIND_GROUP_USER_JOIN_REQUEST_9021, KIND_GROUP_USER_LEAVE_REQUEST_9022,
};

#[derive(Debug, Clone)]
pub struct ValidationMiddleware {
    relay_pubkey: PublicKey,
    pubkey_whitelist: Vec<PublicKey>,
    pubkey_blacklist: Vec<PublicKey>,
}

impl ValidationMiddleware {
    pub fn new(
        relay_pubkey: PublicKey,
        pubkey_whitelist: Vec<PublicKey>,
        pubkey_blacklist: Vec<PublicKey>,
    ) -> Self {
        Self {
            relay_pubkey,
            pubkey_whitelist,
            pubkey_blacklist,
        }
    }

    fn is_allowed(&self, pubkey: &PublicKey) -> bool {
        if pubkey == &self.relay_pubkey {
            return true;
        }
        if self.pubkey_blacklist.contains(pubkey) {
            return false;
        }
        if !self.pubkey_whitelist.is_empty() && !self.pubkey_whitelist.contains(pubkey) {
            return false;
        }
        true
    }

    fn validate_event(&self, event: &Event) -> Result<(), &'static str> {
        // If the event is from the relay pubkey and has a 'd' tag, allow it.
        if event.pubkey == self.relay_pubkey && event.tags.find(TagKind::d()).is_some() {
            return Ok(());
        }

        // For all other cases, require an 'h' tag for group events unless the kind is in the non-group allowed set.
        if event.tags.find(TagKind::h()).is_none() && !NON_GROUP_ALLOWED_KINDS.contains(&event.kind)
        {
            return Err("invalid: group events must contain an 'h' tag");
        }

        Ok(())
    }

    // This was too much, may remove it
    #[allow(unused)]
    fn validate_filter(
        &self,
        filter: &Filter,
        authed_pubkey: Option<&PublicKey>,
    ) -> Result<(), &'static str> {
        // If the authed pubkey is the relay's pubkey, skip validation.
        if authed_pubkey == Some(&self.relay_pubkey) {
            debug!("Skipping filter validation for relay pubkey");
            return Ok(());
        }

        // Check if filter has either 'h' or 'd' tag.
        let has_h_tag = filter
            .generic_tags
            .contains_key(&SingleLetterTag::lowercase(Alphabet::H));

        let has_d_tag = filter
            .generic_tags
            .contains_key(&SingleLetterTag::lowercase(Alphabet::D));

        // Check if kinds are supported (if specified).
        let has_valid_kinds = if let Some(kinds) = &filter.kinds {
            kinds.iter().all(|kind| {
                NON_GROUP_ALLOWED_KINDS.contains(kind)
                    || matches!(
                        kind,
                        k if *k == KIND_GROUP_CREATE_9007
                            || *k == KIND_GROUP_DELETE_9008
                            || *k == KIND_GROUP_ADD_USER_9000
                            || *k == KIND_GROUP_REMOVE_USER_9001
                            || *k == KIND_GROUP_EDIT_METADATA_9002
                            || *k == KIND_GROUP_DELETE_EVENT_9005
                            || *k == KIND_GROUP_SET_ROLES_9006
                            || *k == KIND_GROUP_CREATE_INVITE_9009
                            || *k == KIND_GROUP_USER_JOIN_REQUEST_9021
                            || *k == KIND_GROUP_USER_LEAVE_REQUEST_9022
                            || ADDRESSABLE_EVENT_KINDS.contains(k)
                    )
            })
        } else {
            false
        };

        // Filter must either have valid tags or valid kinds.
        if !has_h_tag && !has_d_tag && !has_valid_kinds {
            return Err("invalid: filter must contain either 'h'/'d' tag or supported kinds");
        }

        Ok(())
    }
}

impl NostrMiddleware<()> for ValidationMiddleware {
    async fn process_inbound<Next>(
        &self,
        ctx: InboundContext<'_, (), Next>,
    ) -> Result<(), anyhow::Error>
    where
        Next: relay_builder::nostr_middleware::InboundProcessor<()>,
    {
        match &ctx.message {
            Some(ClientMessage::Auth(event)) => {
                if !self.is_allowed(&event.pubkey) {
                    warn!(
                        "[{}] Auth rejected for pubkey {} (whitelist/blacklist)",
                        ctx.connection_id, event.pubkey
                    );
                    ctx.send_message(RelayMessage::notice(
                        "restricted: pubkey not allowed on this relay",
                    ))?;
                    return Ok(());
                }
                ctx.next().await
            }
            Some(ClientMessage::Event(event)) => {
                if !self.is_allowed(&event.pubkey) {
                    warn!(
                        "[{}] Event {} rejected for pubkey {} (whitelist/blacklist)",
                        ctx.connection_id, event.id, event.pubkey
                    );
                    ctx.send_message(RelayMessage::ok(
                        event.id,
                        false,
                        "blocked: pubkey not allowed on this relay",
                    ))?;
                    return Ok(());
                }

                debug!(
                    "[{}] Validating event kind {} with id {}",
                    ctx.connection_id, event.kind, event.id
                );

                if let Err(reason) = self.validate_event(event) {
                    warn!(
                        "[{}] Event {} validation failed: {}",
                        ctx.connection_id, event.id, reason
                    );
                    ctx.send_message(RelayMessage::ok(event.id, false, reason))?;
                    return Ok(());
                }

                ctx.next().await
            }
            _ => ctx.next().await,
        }
    }
}

// TODO: Update tests to use the new NostrMiddleware API
// #[cfg(test)]
// mod tests {
//     use super::*;
//     // Tests temporarily disabled during API migration
// }
