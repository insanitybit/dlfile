use std::convert::TryInto;
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
    SeccompFilter, SeccompRule
};

use eyre::ErrReport;

// Sandboxing for linux only
#[cfg(not(target_os = "linux"))]
pub(crate) fn sandbox() -> Result<(), ErrReport> {
  Ok(())
}

// The "second stage" of the sandbox, after the request has been made but
// before the file has been streamed back
// At this point it's unlikely that further restrictions will really matter,
// but... there we are
#[cfg(target_os = "linux")]
pub(crate) fn sandbox2() -> Result<(), ErrReport> {
let filter: BpfProgram = SeccompFilter::new(
    vec![
        (libc::SYS_accept4, vec![]),
	
//(libc::SYS_fsopen, vec![]),
(libc::SYS_futex, vec![]),
(libc::SYS_read, vec![
    SeccompRule::new(vec![
	// We only ever read fd 10
        SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 10)?,
        // Because seccomp can't validate values behind pointers we're unable to do much at all
        SeccompCondition::new(1, SeccompCmpArgLen::Qword, SeccompCmpOp::Gt, 0u64)?,
        // We always read more than 0 bytes...
        SeccompCondition::new(2, SeccompCmpArgLen::Dword, SeccompCmpOp::Gt, 0u64)?,
    ])?,
]),
(libc::SYS_close, vec![]),
(libc::SYS_write, vec![]),
(libc::SYS_sigaltstack, vec![]),
(libc::SYS_munmap, vec![]),
(libc::SYS_exit_group, vec![]),

    ]
    .into_iter()
    .collect(),
    SeccompAction::KillProcess,
    SeccompAction::Allow,
    std::env::consts::ARCH.try_into()?,
).unwrap().try_into().unwrap();
seccompiler::apply_filter(&filter)?;

  Ok(())
}


// todo: socketpair AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK
// mprotect - no exec
#[cfg(target_os = "linux")]
pub(crate) fn sandbox() -> Result<(), ErrReport> {
let filter: BpfProgram = SeccompFilter::new(
    vec![
        (libc::SYS_accept4, vec![]),
	
//(libc::SYS_fsopen, vec![]),
(libc::SYS_fspick, vec![]),
(libc::SYS_fstat, vec![]),
(libc::SYS_fstatfs, vec![]),
(libc::SYS_fsync, vec![]),
(libc::SYS_futex, vec![]),
// Used to open /etc/resolve.conf and /etc/hosts
(libc::SYS_openat, vec![
    SeccompRule::new(vec![
	// Really doesn't do much except specify that the path is relative to cwd
        SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, libc::AT_FDCWD as u64)?,
        // Because seccomp can't validate values behind pointers we're unable to do much at all
        SeccompCondition::new(1, SeccompCmpArgLen::Qword, SeccompCmpOp::Gt, 0u64)?, 
        // Read only, close when fd is closed.
        SeccompCondition::new(2, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, (libc::O_RDONLY | libc::O_CLOEXEC) as u64)?,
    ]).unwrap(),
]),
// Used to stat /etc/resolve.conf
(libc::SYS_statx, vec![]),
(libc::SYS_lseek, vec![
    SeccompRule::new(vec![
	// We only ever open fd 10
        SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 10).unwrap(),
	// We always seek to 0
        SeccompCondition::new(1, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, 0u64).unwrap(),
	// No idea what SEEK_CUR is tbh
        SeccompCondition::new(2, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, libc::SEEK_CUR as u64).unwrap(),
    ]).unwrap(),
]),
(libc::SYS_read, vec![
    SeccompRule::new(vec![
	// We only ever read fd 10
        SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 10).unwrap(),
        // Because seccomp can't validate values behind pointers we're unable to do much at all
        SeccompCondition::new(1, SeccompCmpArgLen::Qword, SeccompCmpOp::Gt, 0u64).unwrap(),
        // We always read more than 0 bytes...
        SeccompCondition::new(2, SeccompCmpArgLen::Dword, SeccompCmpOp::Gt, 0u64).unwrap(),
    ]).unwrap(),
]),
(libc::SYS_close, vec![]),
(libc::SYS_prctl, vec![]),
(libc::SYS_brk, vec![]),
(libc::SYS_write, vec![]),
(libc::SYS_getrandom, vec![]),
(libc::SYS_socket, vec![
    // dns
    SeccompRule::new(vec![
	// Specify socket address family
        SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, libc::AF_INET as u64).unwrap(),
        // Because seccomp can't validate values behind pointers we're unable to do much at all
        SeccompCondition::new(1, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, ( libc::SOCK_DGRAM|libc::SOCK_CLOEXEC|libc::SOCK_NONBLOCK) as u64).unwrap(),
        // Read only, close when fd is closed.
        SeccompCondition::new(2, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, libc::IPPROTO_IP as u64).unwrap(),
    ]).unwrap(),

]),
(libc::SYS_bind, vec![]),
(libc::SYS_epoll_ctl, vec![]),
(libc::SYS_sendto, vec![]),
(libc::SYS_recvfrom, vec![]),
(libc::SYS_fcntl, vec![]),
(libc::SYS_socket, vec![]),
(libc::SYS_connect, vec![]),
(libc::SYS_getsockopt, vec![]),
(libc::SYS_setsockopt, vec![]),
(libc::SYS_writev, vec![]),
(libc::SYS_getpeername, vec![]),
(libc::SYS_sched_yield, vec![]),
(libc::SYS_sigaltstack, vec![]),
(libc::SYS_munmap, vec![]),
(libc::SYS_exit_group, vec![]),

    ]
    .into_iter()
    .collect(),
    SeccompAction::KillProcess,
    SeccompAction::Allow,
    std::env::consts::ARCH.try_into().unwrap(),
).unwrap().try_into().unwrap();
seccompiler::apply_filter(&filter).unwrap();

  Ok(())
}

