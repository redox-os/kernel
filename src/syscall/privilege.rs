use alloc::vec::Vec;

use crate::{
    context,
    scheme::{self, SchemeNamespace},
    syscall::error::*,
};

use super::{
    copy_path_to_buf,
    usercopy::{UserSlice, UserSliceRo},
};

pub fn getegid() -> Result<usize> {
    let contexts = context::contexts();
    let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
    let context = context_lock.read();
    Ok(context.egid as usize)
}

pub fn getens() -> Result<usize> {
    let contexts = context::contexts();
    let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
    let context = context_lock.read();
    Ok(context.ens.into())
}

pub fn geteuid() -> Result<usize> {
    let contexts = context::contexts();
    let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
    let context = context_lock.read();
    Ok(context.euid as usize)
}

pub fn getgid() -> Result<usize> {
    let contexts = context::contexts();
    let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
    let context = context_lock.read();
    Ok(context.rgid as usize)
}

pub fn getns() -> Result<usize> {
    let contexts = context::contexts();
    let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
    let context = context_lock.read();
    Ok(context.rns.into())
}

pub fn getuid() -> Result<usize> {
    let contexts = context::contexts();
    let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
    let context = context_lock.read();
    Ok(context.ruid as usize)
}

pub fn mkns(mut user_buf: UserSliceRo) -> Result<usize> {
    let (uid, from) = match context::current()?.read() {
        ref context => (context.euid, context.ens),
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

pub fn setregid(rgid: u32, egid: u32) -> Result<usize> {
    let contexts = context::contexts();
    let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
    let mut context = context_lock.write();

    let setrgid = if context.euid == 0 {
        // Allow changing RGID if root
        true
    } else if rgid == context.egid {
        // Allow changing RGID if used for EGID
        true
    } else if rgid == context.rgid {
        // Allow changing RGID if used for RGID
        true
    } else if rgid as i32 == -1 {
        // Ignore RGID if -1 is passed
        false
    } else {
        // Not permitted otherwise
        return Err(Error::new(EPERM));
    };

    let setegid = if context.euid == 0 {
        // Allow changing EGID if root
        true
    } else if egid == context.egid {
        // Allow changing EGID if used for EGID
        true
    } else if egid == context.rgid {
        // Allow changing EGID if used for RGID
        true
    } else if egid as i32 == -1 {
        // Ignore EGID if -1 is passed
        false
    } else {
        // Not permitted otherwise
        return Err(Error::new(EPERM));
    };

    if setrgid {
        context.rgid = rgid;
    }

    if setegid {
        context.egid = egid;
    }

    Ok(0)
}

pub fn setrens(rns: SchemeNamespace, ens: SchemeNamespace) -> Result<usize> {
    let contexts = context::contexts();
    let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
    let mut context = context_lock.write();

    let setrns = if rns.get() as isize == -1 {
        // Ignore RNS if -1 is passed
        false
    } else if rns.get() == 0 {
        // Allow entering capability mode
        true
    } else if context.rns.get() == 0 {
        // Do not allow leaving capability mode
        return Err(Error::new(EPERM));
    } else if context.euid == 0 {
        // Allow setting RNS if root
        true
    } else if rns == context.ens {
        // Allow setting RNS if used for ENS
        true
    } else if rns == context.rns {
        // Allow setting RNS if used for RNS
        true
    } else {
        // Not permitted otherwise
        return Err(Error::new(EPERM));
    };

    let setens = if ens.get() as isize == -1 {
        // Ignore ENS if -1 is passed
        false
    } else if ens.get() == 0 {
        // Allow entering capability mode
        true
    } else if context.ens.get() == 0 {
        // Do not allow leaving capability mode
        return Err(Error::new(EPERM));
    } else if context.euid == 0 {
        // Allow setting ENS if root
        true
    } else if ens == context.ens {
        // Allow setting ENS if used for ENS
        true
    } else if ens == context.rns {
        // Allow setting ENS if used for RNS
        true
    } else {
        // Not permitted otherwise
        return Err(Error::new(EPERM));
    };

    if setrns {
        assert_ne!(rns.get() as isize, -1);
        context.rns = rns;
    }

    if setens {
        assert_ne!(ens.get() as isize, -1);
        context.ens = ens;
    }

    Ok(0)
}

pub fn setreuid(ruid: u32, euid: u32) -> Result<usize> {
    let contexts = context::contexts();
    let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
    let mut context = context_lock.write();

    let setruid = if context.euid == 0 {
        // Allow setting RUID if root
        true
    } else if ruid == context.euid {
        // Allow setting RUID if used for EUID
        true
    } else if ruid == context.ruid {
        // Allow setting RUID if used for RUID
        true
    } else if ruid as i32 == -1 {
        // Ignore RUID if -1 is passed
        false
    } else {
        // Not permitted otherwise
        return Err(Error::new(EPERM));
    };

    let seteuid = if context.euid == 0 {
        // Allow setting EUID if root
        true
    } else if euid == context.euid {
        // Allow setting EUID if used for EUID
        true
    } else if euid == context.ruid {
        // Allow setting EUID if used for RUID
        true
    } else if euid as i32 == -1 {
        // Ignore EUID if -1 is passed
        false
    } else {
        // Not permitted otherwise
        return Err(Error::new(EPERM));
    };

    if setruid {
        context.ruid = ruid;
    }

    if seteuid {
        context.euid = euid;
    }

    Ok(0)
}
