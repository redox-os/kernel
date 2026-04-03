use crate::{
    ipi::{ipi, IpiKind, IpiTarget},
    memory::RmmA,
};

pub use rmm::{Flusher, PageFlush};

pub struct InactiveFlusher {
    _inner: (),
}
impl Flusher<RmmA> for InactiveFlusher {
    fn consume(&mut self, flush: PageFlush<RmmA>) {
        // TODO: Push to TLB "mailbox" or tell it to reload CR3 if there are too many entries.
        unsafe {
            flush.ignore();
        }
    }
}
impl Drop for InactiveFlusher {
    fn drop(&mut self) {
        ipi(IpiKind::Tlb, IpiTarget::Other);
    }
}
