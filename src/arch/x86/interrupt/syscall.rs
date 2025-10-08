use crate::{
    ptrace,
    sync::CleanLockToken,
    syscall,
    syscall::flag::{PTRACE_FLAG_IGNORE, PTRACE_STOP_POST_SYSCALL, PTRACE_STOP_PRE_SYSCALL},
};

pub unsafe fn init() {}

macro_rules! with_interrupt_stack {
    (|$stack:ident, $token:ident| $code:block) => {{
        let mut $token = CleanLockToken::new();

        let allowed = ptrace::breakpoint_callback(PTRACE_STOP_PRE_SYSCALL, None, &mut $token)
            .and_then(|_| ptrace::next_breakpoint().map(|f| !f.contains(PTRACE_FLAG_IGNORE)));

        if allowed.unwrap_or(true) {
            // If the syscall is `clone`, the clone won't return here. Instead,
            // it'll return early and leave any undropped values. This is
            // actually GOOD, because any references are at that point UB
            // anyway, because they are based on the wrong stack.
            let $stack = &mut *$stack;
            $code
        }

        ptrace::breakpoint_callback(PTRACE_STOP_POST_SYSCALL, None, &mut $token);
    }};
}

interrupt_stack!(syscall, |stack| {
    with_interrupt_stack!(|stack, token| {
        let scratch = &stack.scratch;
        let preserved = &stack.preserved;
        let ret = syscall::syscall(
            scratch.eax,
            preserved.ebx,
            scratch.ecx,
            scratch.edx,
            preserved.esi,
            preserved.edi,
            &mut token,
        );
        stack.scratch.eax = ret;
    })
});

pub use super::handler::enter_usermode;
