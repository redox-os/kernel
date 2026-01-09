// This code was adapted from MIT licensed https://github.com/antialize/ordered-locks
// We cannot use that library directly as it is wrapping std::sync types

#![allow(dead_code)]

//! This crate implements compiletime ordering of locks into levels, [`L1`], [`L2`], [`L3`], [`L4`] and [`L5`].
//! In order to acquire a lock at level `i` only locks at level `i-1` or below may be held.
//!
//! If locks are always acquired in level order on all threads, then one cannot have a deadlock
//! involving only acquired locks.
//!
//! In the following example we create two [mutexes](Mutex) at level [`L1`] and [`L2`] and lock them
//! in the propper order.
//! ```
//! use ordered_locks::{L1, L2, Mutex, CleanLockToken};
//! // Create value at lock level 0, this lock cannot be acquired while a level1 lock is heldt
//! let v1 = Mutex::<L1, _>::new(42);
//! // Create value at lock level 1
//! let v2 = Mutex::<L2, _>::new(43);
//! // Construct a token indicating that this thread does not hold any locks
//! let mut token = unsafe {CleanLockToken::new()};
//!
//! {
//!     // We can acquire the locks for v1 and v2 at the same time
//!     let mut g1 = v1.lock(token.token());
//!     let (g1, token) = g1.token_split();
//!     let mut g2 = v2.lock(token);
//!     *g2 = 11;
//!     *g1 = 12;
//! }
//! // Once the guards are dropped we can acquire other things
//! *v2.lock(token.token()) = 13;
//! ```
//!
//! In the following example we create two [mutexes](Mutex) at level [`L1`] and [`L2`] and try to lock
//! the mutex at [`L1`] while already holding a [`Mutex`] at [`L2`] which failes to compile.
//! ```compile_fail
//! use ordered_locks::{L1, L2, Mutex, CleanLockToken};
//! // Create value at lock level 0, this lock cannot be acquired while a level1 lock is heldt
//! let v1 = Mutex::<L1, _>::new(42);
//! // Create value at lock level 1
//! let v2 = Mutex::<L2, _>::new(43);
//! // Construct a token indicating that this thread does not hold any locks
//! let mut clean_token = unsafe {CleanLockToken::new()};
//! let token = clean_token.token();
//!
//! // Try to aquire locks in the wrong order
//! let mut g2 = v2.lock(token);
//! let (g2, token) = g2.token_split();
//! let mut g1 = v1.lock(token); // shouldn't compile!
//! *g2 = 11;
//! *g1 = 12;
//! ```
use alloc::sync::Arc;
use core::marker::PhantomData;

/// Lock level of a mutex
///
/// While a mutex of L1 is locked on a thread, only mutexes of L2 or higher may be locked.
/// This lock hierarchy prevents deadlocks from occurring. For a deadlock to occur
/// We need some thread TA to hold a resource RA, and request a resource RB, while
/// another thread TB holds RB, and requests RA. This is not possible with a lock
/// hierarchy either RA or RB must be on a level that the other.
///
/// At some point in time we would want Level to be replaced by usize, however
/// with current const generics (rust 1.55), we cannot compare const generic arguments
/// so we are left with this mess.
pub trait Level {}

/// Indicate that the implementor is lower that the level O
pub trait Lower<O: Level>: Level {}

/// Lowest locking level, no locks can be on this level
#[derive(Debug)]
pub struct L0 {}

#[derive(Debug)]
pub struct L1 {}

#[derive(Debug)]
pub struct L2 {}

#[derive(Debug)]
pub struct L3 {}

#[derive(Debug)]
pub struct L4 {}

#[derive(Debug)]
pub struct L5 {}

impl Level for L0 {}
impl Level for L1 {}
impl Level for L2 {}
impl Level for L3 {}
impl Level for L4 {}
impl Level for L5 {}

impl Lower<L1> for L0 {}
impl Lower<L2> for L0 {}
impl Lower<L3> for L0 {}
impl Lower<L4> for L0 {}
impl Lower<L5> for L0 {}

impl Lower<L2> for L1 {}
impl Lower<L3> for L1 {}
impl Lower<L4> for L1 {}
impl Lower<L5> for L1 {}

impl Lower<L3> for L2 {}
impl Lower<L4> for L2 {}
impl Lower<L5> for L2 {}

impl Lower<L4> for L3 {}
impl Lower<L5> for L3 {}

impl Lower<L5> for L4 {}

/// Indicate that the implementor is higher that the level O
pub trait Higher<O: Level>: Level {}
impl<L1: Level, L2: Level> Higher<L2> for L1 where L2: Lower<L1> {}

/// While this exists only locks with a level higher than L, may be locked.
/// These tokens are carried around the call stack to indicate the current locking level.
/// They have no size and should disappear at runtime.
pub struct LockToken<'a, L: Level>(PhantomData<&'a mut L>);

impl<'a, L: Level> LockToken<'a, L> {
    /// Create a borrowed copy of self
    pub fn token(&mut self) -> LockToken<'_, L> {
        LockToken(Default::default())
    }

    /// Create a borrowed copy of self, on a higher level
    pub fn downgrade<LC: Higher<L>>(&mut self) -> LockToken<'_, LC> {
        LockToken(Default::default())
    }

    pub fn downgraded<LP: Lower<L>>(_: LockToken<'a, LP>) -> Self {
        LockToken(Default::default())
    }
}

/// Token indicating that there are no acquired locks while not borrowed.
pub struct CleanLockToken(());

impl CleanLockToken {
    /// Create a borrowed copy of self
    pub fn token(&mut self) -> LockToken<'_, L0> {
        LockToken(Default::default())
    }

    /// Create a borrowed copy of self, on a higher level
    pub fn downgrade<L: Level>(&mut self) -> LockToken<'_, L> {
        LockToken(Default::default())
    }

    /// Create a new instance
    ///
    /// # Safety
    ///
    /// This is safe to call as long as there are no currently acquired locks
    /// in the thread/task, and as long as there are no other CleanLockToken
    /// in the thread/task.
    ///
    /// A CleanLockToken
    pub unsafe fn new() -> Self {
        CleanLockToken(())
    }
}

/// A mutual exclusion primitive useful for protecting shared data
///
/// This mutex will block threads waiting for the lock to become available. The
/// mutex can also be statically initialized or created via a `new`
/// constructor. Each mutex has a type parameter which represents the data that
/// it is protecting. The data can only be accessed through the RAII guards
/// returned from `lock` and `try_lock`, which guarantees that the data is only
/// ever accessed when the mutex is locked.
#[derive(Debug)]
pub struct Mutex<L: Level, T> {
    inner: spin::Mutex<T>,
    _phantom: PhantomData<L>,
}

impl<L: Level, T: Default> Default for Mutex<L, T> {
    fn default() -> Self {
        Self {
            inner: Default::default(),
            _phantom: Default::default(),
        }
    }
}

impl<L: Level, T> Mutex<L, T> {
    /// Creates a new mutex in an unlocked state ready for use
    pub const fn new(val: T) -> Self {
        Self {
            inner: spin::Mutex::new(val),
            _phantom: PhantomData,
        }
    }

    /// Acquires a mutex, blocking the current thread until it is able to do so.
    ///
    /// This function will block the local thread until it is available to acquire the mutex.
    /// Upon returning, the thread is the only thread with the mutex held.
    /// An RAII guard is returned to allow scoped unlock of the lock. When the guard goes out of scope, the mutex will be unlocked.
    pub fn lock<'a, LP: Lower<L> + 'a>(
        &'a self,
        lock_token: LockToken<'a, LP>,
    ) -> MutexGuard<'a, L, T> {
        MutexGuard {
            inner: self.inner.lock(),
            lock_token: LockToken::downgraded(lock_token),
        }
    }

    /// Attempts to acquire this lock.
    ///
    /// If the lock could not be acquired at this time, then `None` is returned.
    /// Otherwise, an RAII guard is returned. The lock will be unlocked when the
    /// guard is dropped.
    ///
    /// This function does not block.
    pub fn try_lock<'a, LP: Lower<L> + 'a>(
        &'a self,
        lock_token: LockToken<'a, LP>,
    ) -> Option<MutexGuard<'a, L, T>> {
        self.inner.try_lock().map(|inner| MutexGuard {
            inner,
            lock_token: LockToken::downgraded(lock_token),
        })
    }

    /// Consumes this Mutex, returning the underlying data.
    pub fn into_inner(self) -> T {
        self.inner.into_inner()
    }
}

/// An RAII implementation of a "scoped lock" of a mutex. When this structure is
/// dropped (falls out of scope), the lock will be unlocked.
///
/// The data protected by the mutex can be accessed through this guard via its
/// `Deref` and `DerefMut` implementations.
pub struct MutexGuard<'a, L: Level, T: ?Sized + 'a> {
    inner: spin::MutexGuard<'a, T>,
    lock_token: LockToken<'a, L>,
}

impl<'a, L: Level, T: ?Sized + 'a> MutexGuard<'a, L, T> {
    /// Split the guard into two parts, the first a mutable reference to the held content
    /// the second a [`LockToken`] that can be used for further locking
    pub fn token_split(&mut self) -> (&mut T, LockToken<'_, L>) {
        (&mut self.inner, self.lock_token.token())
    }
}

impl<'a, L: Level, T: ?Sized + 'a> core::ops::Deref for MutexGuard<'a, L, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}
impl<'a, L: Level, T: ?Sized + 'a> core::ops::DerefMut for MutexGuard<'a, L, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.deref_mut()
    }
}

pub struct RwLock<L: Level, T> {
    inner: spin::RwLock<T>,
    _phantom: PhantomData<L>,
}

impl<L: Level, T: Default> Default for RwLock<L, T> {
    fn default() -> Self {
        Self {
            inner: Default::default(),
            _phantom: Default::default(),
        }
    }
}

/// A reader-writer lock
///
/// This type of lock allows a number of readers or at most one writer at any point in time.
/// The write portion of this lock typically allows modification of the underlying data (exclusive access)
/// and the read portion of this lock typically allows for read-only access (shared access).
///
/// The type parameter T represents the data that this lock protects. It is required that T satisfies
/// Send to be shared across threads and Sync to allow concurrent access through readers.
/// The RAII guards returned from the locking methods implement Deref (and DerefMut for the write methods)
/// to allow access to the container of the lock.
impl<L: Level, T> RwLock<L, T> {
    /// Creates a new instance of an RwLock<T> which is unlocked.
    pub const fn new(val: T) -> Self {
        Self {
            inner: spin::RwLock::new(val),
            _phantom: PhantomData,
        }
    }

    /// Consumes this RwLock, returning the underlying data.
    pub fn into_inner(self) -> T {
        self.inner.into_inner()
    }

    /// Locks this RwLock with exclusive write access, blocking the current thread until it can be acquired.
    /// This function will not return while other writers or other readers currently have access to the lock.
    /// Returns an RAII guard which will drop the write access of this RwLock when dropped.
    pub fn write<'a, LP: Lower<L> + 'a>(
        &'a self,
        lock_token: LockToken<'a, LP>,
    ) -> RwLockWriteGuard<'a, L, T> {
        RwLockWriteGuard {
            inner: self.inner.write(),
            lock_token: LockToken::downgraded(lock_token),
        }
    }

    /// Locks this RwLock with shared read access, blocking the current thread until it can be acquired.
    ///
    /// The calling thread will be blocked until there are no more writers which hold the lock.
    /// There may be other readers currently inside the lock when this method returns.
    ///
    /// Note that attempts to recursively acquire a read lock on a RwLock when the current thread
    /// already holds one may result in a deadlock.
    ///
    /// Returns an RAII guard which will release this thread’s shared access once it is dropped.
    pub fn read<'a, LP: Lower<L> + 'a>(
        &'a self,
        lock_token: LockToken<'a, LP>,
    ) -> RwLockReadGuard<'a, L, T> {
        RwLockReadGuard {
            inner: self.inner.read(),
            lock_token: LockToken::downgraded(lock_token),
        }
    }

    // Unsafe due to not using token, currently required by context::switch
    pub unsafe fn write_arc(self: &Arc<Self>) -> ArcRwLockWriteGuard<L, T> {
        core::mem::forget(self.inner.write());
        ArcRwLockWriteGuard {
            rwlock: self.clone(),
        }
    }
}

/// RAII structure used to release the exclusive write access of a lock when dropped
pub struct RwLockWriteGuard<'a, L: Level, T> {
    inner: spin::RwLockWriteGuard<'a, T>,
    lock_token: LockToken<'a, L>,
}

impl<L: Level, T> RwLockWriteGuard<'_, L, T> {
    /// Split the guard into two parts, the first a mutable reference to the held content
    /// the second a [`LockToken`] that can be used for further locking
    pub fn token_split(&mut self) -> (&mut T, LockToken<'_, L>) {
        (&mut self.inner, self.lock_token.token())
    }
}

impl<L: Level, T> core::ops::Deref for RwLockWriteGuard<'_, L, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl<L: Level, T> core::ops::DerefMut for RwLockWriteGuard<'_, L, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.deref_mut()
    }
}

/// RAII structure used to release the shared read access of a lock when dropped.
pub struct RwLockReadGuard<'a, L: Level, T> {
    inner: spin::RwLockReadGuard<'a, T>,
    lock_token: LockToken<'a, L>,
}

impl<L: Level, T> RwLockReadGuard<'_, L, T> {
    /// Split the guard into two parts, the first a reference to the held content
    /// the second a [`LockToken`] that can be used for further locking
    pub fn token_split(&mut self) -> (&T, LockToken<'_, L>) {
        (&self.inner, self.lock_token.token())
    }
}

impl<L: Level, T> core::ops::Deref for RwLockReadGuard<'_, L, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

pub struct ArcRwLockWriteGuard<L: Level + 'static, T> {
    rwlock: Arc<RwLock<L, T>>,
}

impl<L: Level, T> ArcRwLockWriteGuard<L, T> {
    pub fn rwlock(s: &Self) -> &Arc<RwLock<L, T>> {
        &s.rwlock
    }
}

impl<L: Level, T> core::ops::Deref for ArcRwLockWriteGuard<L, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.rwlock.inner.as_mut_ptr() }
    }
}

impl<L: Level, T> core::ops::DerefMut for ArcRwLockWriteGuard<L, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.rwlock.inner.as_mut_ptr() }
    }
}

impl<L: Level, T> Drop for ArcRwLockWriteGuard<L, T> {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            self.rwlock.inner.force_write_unlock();
        }
    }
}

/// This function can only be called if no lock is held by the calling thread/task
#[inline]
pub fn check_no_locks(_: LockToken<'_, L0>) {}
