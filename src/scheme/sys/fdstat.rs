use crate::{
    alloc::string::ToString,
    context::{contexts, file::LockedFileDescription, memory::AddrSpaceWrapper},
    scheme::{self, handles, KernelSchemes},
    sync::CleanLockToken,
    syscall::error::Result,
};
use alloc::{borrow::Cow, string::String, sync::Arc, vec::Vec};
use core::{fmt::Write, hash::Hash};
use hashbrown::HashMap;
use lfll::List;

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
    scheme: Cow<'static, str>,
    number: usize,
}

#[cfg_attr(not(feature = "sys_fdstat"), expect(dead_code))]
pub fn resource(token: &mut CleanLockToken) -> Result<Vec<u8>> {
    let mut map = HashMap::<Ref<LockedFileDescription>, Descr>::new();
    let mut report = String::new();
    let mut schemes_guard = handles().read(token.token());
    let (schemes, mut token) = schemes_guard.token_split();

    'contexts: for context in contexts().iter().filter_map(|(_, x)| x.upgrade()) {
        let mut context_guard = context.read(token.token());
        let (context, token) = context_guard.token_split();
        let mut files_guard = context.files.read(token);
        let (files, mut token) = files_guard.token_split();
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

            let scheme_id = file.description.read(token.token()).scheme;
            let scheme = schemes.get(&scheme_id);
            descr
                .owners
                .entry(Ref(a))
                .or_insert(context.name.clone().to_string());
            descr.scheme = match scheme {
                Some(scheme::Handle::SchemeCreationCapability) => "SchemeCreationCapability".into(),
                Some(scheme::Handle::Scheme(KernelSchemes::Global(g))) => g.as_str().into(),
                Some(scheme::Handle::Scheme(KernelSchemes::User(scheme))) => {
                    format!("[user {:p}]", Arc::as_ptr(&scheme.inner)).into()
                }
                Some(scheme::Handle::Scheme(KernelSchemes::SchemeMgr)) => "SchemeMgr".into(),
                _ => format!("[unknown {}]", scheme_id.0).into(),
            };
            descr.number = file.description.read(token.token()).number;
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
            "{:p}: {:?}; {}:{}",
            fr.0,
            ma.owners.values().cloned().collect::<Vec<_>>(),
            ma.scheme,
            ma.number,
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
