use alloc::vec::Vec;

use crate::{context, scheme, syscall::error::*};

use super::{
    copy_path_to_buf,
    usercopy::{UserSlice, UserSliceRo},
};

pub fn mkns(mut user_buf: UserSliceRo) -> Result<usize> {
    let (uid, from) = match context::current().read() {
        ref cx => (cx.euid, cx.ens),
    };

    // TODO: Lift this restriction later?
    if uid != 0 {
        return Err(Error::new(EACCES));
    }

    let mut names = Vec::with_capacity(user_buf.len() / core::mem::size_of::<[usize; 2]>());

    while let Some((current_name_ptr_buf, next_part)) =
        user_buf.split_at(core::mem::size_of::<[usize; 2]>())
    {
        let mut iter = current_name_ptr_buf.usizes();
        let ptr = iter.next().ok_or(Error::new(EINVAL))??;
        let len = iter.next().ok_or(Error::new(EINVAL))??;

        let raw_path = UserSlice::new(ptr, len)?;

        // TODO: Max scheme size limit?
        let max_len = 256;

        names.push(copy_path_to_buf(raw_path, max_len)?.into_boxed_str());

        user_buf = next_part;
    }

    let to = scheme::schemes_mut().make_ns(from, names)?;
    Ok(to.into())
}
