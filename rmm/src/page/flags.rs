use core::{fmt, marker::PhantomData};

use crate::Arch;

#[derive(Clone, Copy)]
pub struct PageFlags<A> {
    data: usize,
    arch: PhantomData<A>,
}

impl<A: Arch> PageFlags<A> {
    #[inline(always)]
    pub fn new() -> Self {
        unsafe {
            Self::from_data(
                // Flags set to present, kernel space, read-only, no-execute by default
                A::ENTRY_FLAG_DEFAULT_PAGE
                    | A::ENTRY_FLAG_READONLY
                    | A::ENTRY_FLAG_NO_EXEC
                    | A::ENTRY_FLAG_NO_GLOBAL,
            )
        }
    }

    #[inline(always)]
    pub fn new_table() -> Self {
        unsafe {
            Self::from_data(
                // Flags set to present, kernel space, read-only, no-execute by default
                A::ENTRY_FLAG_DEFAULT_TABLE | A::ENTRY_FLAG_NO_EXEC | A::ENTRY_FLAG_NO_GLOBAL,
            )
        }
    }

    #[inline(always)]
    pub unsafe fn from_data(data: usize) -> Self {
        Self {
            data,
            arch: PhantomData,
        }
    }

    #[inline(always)]
    pub fn data(&self) -> usize {
        self.data
    }

    #[must_use]
    #[inline(always)]
    pub fn custom_flag(mut self, flag: usize, value: bool) -> Self {
        if value {
            self.data |= flag;
        } else {
            self.data &= !flag;
        }
        self
    }

    #[must_use]
    #[inline(always)]
    pub fn write_combining(self, value: bool) -> Self {
        self.custom_flag(A::ENTRY_FLAG_WRITE_COMBINING, value)
    }

    #[inline(always)]
    pub fn has_flag(&self, flag: usize) -> bool {
        self.data & flag == flag
    }

    #[inline(always)]
    pub fn has_present(&self) -> bool {
        self.has_flag(A::ENTRY_FLAG_PRESENT)
    }

    #[must_use]
    #[inline(always)]
    pub fn user(self, value: bool) -> Self {
        self.custom_flag(A::ENTRY_FLAG_PAGE_USER, value)
    }

    #[inline(always)]
    pub fn has_user(&self) -> bool {
        self.has_flag(A::ENTRY_FLAG_PAGE_USER)
    }

    #[must_use]
    #[inline(always)]
    pub fn write(self, value: bool) -> Self {
        // Architecture may use readonly or readwrite, or both, support either
        if value {
            self.custom_flag(A::ENTRY_FLAG_READONLY | A::ENTRY_FLAG_READWRITE, false)
                .custom_flag(A::ENTRY_FLAG_READWRITE, true)
        } else {
            self.custom_flag(A::ENTRY_FLAG_READONLY | A::ENTRY_FLAG_READWRITE, false)
                .custom_flag(A::ENTRY_FLAG_READONLY, true)
        }
    }

    #[inline(always)]
    pub fn has_write(&self) -> bool {
        // Architecture may use readonly or readwrite, or both, support either
        self.data & (A::ENTRY_FLAG_READONLY | A::ENTRY_FLAG_READWRITE) == A::ENTRY_FLAG_READWRITE
    }

    #[must_use]
    #[inline(always)]
    pub fn execute(self, value: bool) -> Self {
        //TODO: write xor execute?
        // Architecture may use no exec or exec, support either
        self.custom_flag(A::ENTRY_FLAG_NO_EXEC, !value)
            .custom_flag(A::ENTRY_FLAG_EXEC, value)
    }

    #[inline(always)]
    pub fn has_execute(&self) -> bool {
        // Architecture may use no exec or exec, support either
        self.data & (A::ENTRY_FLAG_NO_EXEC | A::ENTRY_FLAG_EXEC) == A::ENTRY_FLAG_EXEC
    }

    #[must_use]
    #[inline(always)]
    pub fn global(self, value: bool) -> Self {
        // Architecture may use global or non global, support either
        self.custom_flag(A::ENTRY_FLAG_NO_GLOBAL, !value)
            .custom_flag(A::ENTRY_FLAG_GLOBAL, value)
    }

    #[inline(always)]
    pub fn is_global(&self) -> bool {
        // Architecture may use global or non global, support either
        self.data & (A::ENTRY_FLAG_GLOBAL | A::ENTRY_FLAG_NO_GLOBAL) == A::ENTRY_FLAG_GLOBAL
    }
}

impl<A: Arch> fmt::Debug for PageFlags<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PageFlags")
            .field("present", &self.has_present())
            .field("write", &self.has_write())
            .field("executable", &self.has_execute())
            .field("user", &self.has_user())
            .field("bits", &format_args!("{:#0x}", self.data))
            .finish()
    }
}
