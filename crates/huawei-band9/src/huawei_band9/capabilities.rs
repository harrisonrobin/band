use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default)]
pub struct SupportedServices {
    pub ids: BTreeSet<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct SupportedCommands {
    pub by_service: BTreeMap<u8, BTreeSet<u8>>,
}

#[derive(Debug, Clone, Default)]
pub struct ExpandCapabilities {
    pub bytes: Vec<u8>,
}

impl SupportedServices {
    pub fn contains(&self, service_id: u8) -> bool {
        self.ids.contains(&service_id)
    }
}

impl SupportedCommands {
    pub fn supports(&self, service_id: u8, command_id: u8) -> bool {
        self.by_service
            .get(&service_id)
            .map(|commands| commands.contains(&command_id))
            .unwrap_or(false)
    }
}
