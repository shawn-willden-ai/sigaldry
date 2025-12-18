use alloc::{boxed::Box, collections::btree_map::BTreeMap, string::String};

use crate::runes::Schema;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConstructionIdentifier(String);

pub trait Construction {
    fn identifier(&self) -> ConstructionIdentifier;
    fn schema(&self) -> Schema;
}

pub struct ConstructionRegistry {
    constructions: BTreeMap<ConstructionIdentifier, Box<dyn Construction>>,
}

impl ConstructionRegistry {
    pub fn new() -> Self {
        Self { constructions: BTreeMap::new() }
    }

    pub fn register(&mut self, construction: Box<dyn Construction>) {
        self.constructions.insert(construction.identifier(), construction);
    }

    pub fn get(&self, identifier: ConstructionIdentifier) -> Option<&Box<dyn Construction>> {
        self.constructions.get(&identifier)
    }
}
