use crate::{
    context,
    context::{file::FileDescription, memory::AddrSpaceWrapper},
    scheme,
    syscall::error::Result,
};
use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::{fmt::Write, hash::Hash};
use hashbrown::HashMap;
use spin::RwLock;

pub fn resource() -> Result<Vec<u8>> {
    #[derive(Debug)]
    struct Ref<T>(Arc<T>);
    impl<T> Hash for Ref<T> {
        fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
            state.write_usize(Arc::as_ptr(&self.0) as usize);
        }
    }
    impl<T> PartialEq for Ref<T> {
        fn eq(&self, other: &Self) -> bool {
            Arc::as_ptr(&self.0) == Arc::as_ptr(&other.0)
        }
    }
    impl<T> Eq for Ref<T> {}
    #[derive(Default)]
    struct Descr {
        owners: HashMap<Ref<AddrSpaceWrapper>, String>,
        scheme: Box<str>,
    }
    let mut map = HashMap::<Ref<RwLock<FileDescription>>, Descr>::new();

    let mut report = String::new();
    'contexts: for context in context::contexts().iter().filter_map(|c| c.upgrade()) {
        let context = context.read();
        let files = context.files.read();
        writeln!(report, "'{}' {{", context.name).unwrap();

        for file in files.iter().filter_map(|f| f.clone()) {
            writeln!(
                report,
                "\tS{}W{}",
                Arc::strong_count(&file.description),
                Arc::weak_count(&file.description)
            )
            .unwrap();
            let fr = Ref(file.description.clone());
            let Some(a) = context.addr_space.clone() else {
                continue 'contexts;
            };
            let descr = map.entry(fr).or_default();

            let scheme_id = file.description.read().scheme;
            let scheme = scheme::schemes()
                .names
                .iter()
                .flat_map(|(_, v)| v.iter())
                .find_map(|(name, id)| {
                    if *id == scheme_id {
                        Some(name.clone())
                    } else {
                        None
                    }
                });
            descr
                .owners
                .entry(Ref(a))
                .or_insert(context.name.clone().into_owned());
            descr.scheme = scheme.unwrap_or(Box::from("[unknown]"));
        }
        writeln!(report, "}}").unwrap();
    }
    writeln!(report, "==========").unwrap();
    let mut singletons = 0;
    for (fr, ma) in map.iter() {
        if ma.owners.len() == 1 {
            singletons += 1;
        }
        writeln!(
            report,
            "{:p}: {:?}; {}",
            fr.0,
            ma.owners.values().cloned().collect::<Vec<_>>(),
            ma.scheme
        )
        .unwrap();
    }
    writeln!(report, "==========").unwrap();
    writeln!(
        report,
        "{} singletons out of {} total",
        singletons,
        map.len()
    )
    .unwrap();

    Ok(report.into())
}
