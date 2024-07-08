use alloc::vec::Vec;

use crate::{
    context::process,
    scheme::{self, SchemeNamespace},
    syscall::error::*,
};

use super::{
    copy_path_to_buf,
    usercopy::{UserSlice, UserSliceRo},
};

pub fn getegid() -> Result<usize> {
    Ok(process::current()?.read().egid as usize)
}

pub fn getens() -> Result<usize> {
    Ok(process::current()?.read().ens.into())
}

pub fn geteuid() -> Result<usize> {
    Ok(process::current()?.read().euid as usize)
}

pub fn getgid() -> Result<usize> {
    Ok(process::current()?.read().rgid as usize)
}

pub fn getns() -> Result<usize> {
    Ok(process::current()?.read().rns.into())
}

pub fn getuid() -> Result<usize> {
    Ok(process::current()?.read().ruid as usize)
}

pub fn mkns(mut user_buf: UserSliceRo) -> Result<usize> {
    let (uid, from) = match process::current()?.read() {
        ref process => (process.euid, process.ens),
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

pub fn setregid(rgid: u32, egid: u32) -> Result<()> {
    let process_lock = process::current()?;
    let mut process = process_lock.write();

    let setrgid = if process.euid == 0 {
        // Allow changing RGID if root
        true
    } else if rgid == process.egid {
        // Allow changing RGID if used for EGID
        true
    } else if rgid == process.rgid {
        // Allow changing RGID if used for RGID
        true
    } else if rgid as i32 == -1 {
        // Ignore RGID if -1 is passed
        false
    } else {
        // Not permitted otherwise
        return Err(Error::new(EPERM));
    };

    let setegid = if process.euid == 0 {
        // Allow changing EGID if root
        true
    } else if egid == process.egid {
        // Allow changing EGID if used for EGID
        true
    } else if egid == process.rgid {
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
        process.rgid = rgid;
    }

    if setegid {
        process.egid = egid;
    }

    Ok(())
}

pub fn setrens(rns: SchemeNamespace, ens: SchemeNamespace) -> Result<()> {
    let process_lock = process::current()?;
    let mut process = process_lock.write();

    let setrns = if rns.get() as isize == -1 {
        // Ignore RNS if -1 is passed
        false
    } else if rns.get() == 0 {
        // Allow entering capability mode
        true
    } else if process.rns.get() == 0 {
        // Do not allow leaving capability mode
        return Err(Error::new(EPERM));
    } else if process.euid == 0 {
        // Allow setting RNS if root
        true
    } else if rns == process.ens {
        // Allow setting RNS if used for ENS
        true
    } else if rns == process.rns {
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
    } else if process.ens.get() == 0 {
        // Do not allow leaving capability mode
        return Err(Error::new(EPERM));
    } else if process.euid == 0 {
        // Allow setting ENS if root
        true
    } else if ens == process.ens {
        // Allow setting ENS if used for ENS
        true
    } else if ens == process.rns {
        // Allow setting ENS if used for RNS
        true
    } else {
        // Not permitted otherwise
        return Err(Error::new(EPERM));
    };

    if setrns {
        assert_ne!(rns.get() as isize, -1);
        process.rns = rns;
    }

    if setens {
        assert_ne!(ens.get() as isize, -1);
        process.ens = ens;
    }

    Ok(())
}

pub fn setreuid(ruid: u32, euid: u32) -> Result<()> {
    let process_lock = process::current()?;
    let mut process = process_lock.write();

    let setruid = if process.euid == 0 {
        // Allow setting RUID if root
        true
    } else if ruid == process.euid {
        // Allow setting RUID if used for EUID
        true
    } else if ruid == process.ruid {
        // Allow setting RUID if used for RUID
        true
    } else if ruid as i32 == -1 {
        // Ignore RUID if -1 is passed
        false
    } else {
        // Not permitted otherwise
        return Err(Error::new(EPERM));
    };

    let seteuid = if process.euid == 0 {
        // Allow setting EUID if root
        true
    } else if euid == process.euid {
        // Allow setting EUID if used for EUID
        true
    } else if euid == process.ruid {
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
        process.ruid = ruid;
    }

    if seteuid {
        process.euid = euid;
    }

    Ok(())
}
