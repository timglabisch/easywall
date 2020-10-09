use nix::unistd;
use std::error::Error;
use libc::syscall;
use nix::unistd::{Pid, execvp};
use nix::sys::{wait, signal};
use nix::sys::ptrace;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::ffi::CString;
use crate::platform::SyscallEntry;

mod platform;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProcessType {
    ClonedThread,
    ForkedProcess,
    MainTracee,
    VForkedProcess,
}

pub fn handle_pid_syscall(
    pid: Pid,
) -> Result<(), String> {

    match ptrace::getregs(pid) {
        Ok(mut regs) => {
            let syscall_id = regs.orig_rax as u32;

            let info = SyscallEntry::new_pre(pid, &regs, syscall_id);

            println!("intercept syscall {}", info.get_description());

            // Execute this child syscall
            ptrace::syscall(pid)
                .map_err(|_| format!("Unable to restart syscall exit for PID {:?}", pid))?
        }
        Err(err) => {
            panic!("could not get ptrace registers");
        }
    }

    Ok(())
}

pub fn wait_child(pid: Pid, nohang: bool) -> Result<nix::sys::wait::WaitStatus, String> {
    if nohang {
        wait::waitpid(
            pid,
            Some(wait::WaitPidFlag::__WALL | wait::WaitPidFlag::WNOHANG),
        )
            .map_err(|e| format!("Unable to wait for child PID {}: {:?}", pid, e))
    } else {
        wait::waitpid(pid, Some(wait::WaitPidFlag::__WALL))
            .map_err(|e| format!("Unable to wait for child PID {}: {:?}", pid, e))
    }
}

/// Handles all `WaitStatus` types returned by `wait_child()` for a specific child process
///
/// # Arguments
///
///   - `wait_status`: status returned by `wait_child()`
///   - `processes`: `ProcessList` which can be modified if the child cloned/forked.
///   - `syscall_handler`: current syscall handler
fn handle_wait_status(
    wait_status: &wait::WaitStatus,
) -> Result<(), String> {
    match wait_status {
        // Handle the continuation of a child process after a stop
        wait::WaitStatus::Continued(pid) => {
            println!("Child process {:?} continued", pid);
            Ok(())
        }

        // Handle exit of a child process
        wait::WaitStatus::Exited(pid, code) => {
            /*
            println!("Child process {:?} exited with code {}", pid, code);
            let mut child = processes.0.get_mut(&pid).ok_or_else(|| format!(
                "Child process {:?} exited, however this process is not in the process list",
                pid
            ))?;
            child.trace_state = ProcessTraceState::Terminated(*code as isize);
             */
            panic!("wait::WaitStatus::Exited");
        }

        // Handle ptrace events such as a clone, fork or exec
        wait::WaitStatus::PtraceEvent(pid, sig, ev_type) => {
            // DEBUG: ptrace events should always use a SIGTRAP
            assert!(*sig == signal::Signal::SIGTRAP);

            // Set flag to continue processing based on event type.  Processing fetches the new PID
            // from the event and updates the child ProcessState accordigly, therefore processing
            // should only continue for clones and forks.
            // TODO: stop using Linux hard-coded event IDs
            let cont = match ev_type {
                1 => {
                    println!("Process {:?} forked", pid);
                    true
                }
                2 => {
                    println!("Process {:?} vforked", pid);
                    true
                }
                3 => {
                    println!("Process {:?} created clone", pid);
                    true
                }
                4 => {
                    println!("Process {:?} called exec", pid);
                    false
                }
                t => {
                    println!("Process {:?}: unknown event type {}", pid, t);
                    false
                }
            };

            if cont {
                let child_pid =
                    ptrace::getevent(*pid).map_err(|_| "Unable to get ptrace event details")?;

                // Get new child PID for clone, fork, etc.
                let child_pid = Pid::from_raw(child_pid as i32);
                println!("New child PID: {:?}", child_pid);

                let child_type = match ev_type {
                    1 => ProcessType::ForkedProcess,
                    2 => ProcessType::VForkedProcess,
                    3 => ProcessType::ClonedThread,
                    _ => ProcessType::ForkedProcess,
                };

            }

            // Restart PID that sent the event (parent of newly-created PID)
            ptrace::syscall(*pid)
                .map_err(|_| format!("Unable to restart PID {:?} for syscall entry wait", pid))?;

            Ok(())
        }

        // When PTRACE_O_TRACESYSGOOD is set, PtraceSyscall will be generated when a process has
        // hit a syscall entery/exit.  Handle the syscall via handle_pid_syscall().
        wait::WaitStatus::PtraceSyscall(pid) => {
            handle_pid_syscall(*pid)
        }

        // Handle a generic signal to a child process: log signal and restart child via
        // ptrace::syscall().
        wait::WaitStatus::Signaled(pid, sig, did_core_dump) => {
            println!("Child process {:?} was given signal {:?}", pid, sig);
            if *did_core_dump {
                println!("Child process {:?} produced a core dump", pid);
            }
            ptrace::syscall(*pid)
                .map_err(|_| format!("Unable to restart PID {:?} for syscall entry wait", pid))?;
            Ok(())
        }

        // StillAlive will not be generated unless WNOHANG waitpid() option is set
        wait::WaitStatus::StillAlive => Ok(()),

        // Stopped: handle new PID, PID just created from PtraceEvent or existing PID by
        // (re)starting it via ptrace::syscall().  Also call handle_pid_stop() for existing PIDs to
        // handle any signals as necessary.
        wait::WaitStatus::Stopped(pid, signal) => {
            panic!("wait::WaitStatus::Stopped");
        }
    }
}

/// Initiates and runs the main tracer loop on a child (tracee) PID
///
/// # Arguments
///
///   - `tracee_pid`: PID of the main tracee process (which should have been executed via `exec_child()`)
///   - `syscall_handler`: current syscall handler
pub fn child_loop(tracee_pid: Pid) -> Result<(), String> {

    // Flag to indicate if a SIGINT has been received
    let sigint = Arc::new(AtomicBool::new(false));

    // UNSAFE: register a handler for SIGINT to close stdin and set the "sigint" flag
    unsafe {
        // Clone the "sigint" Arc to move to closure
        let sigint = Arc::clone(&sigint);
        let sigint2 = Arc::clone(&sigint);

        signal_hook::register(signal_hook::SIGINT, move || {
            // Close stdin explicitly. This will abort any user input (io::stdin().read_line())
            // that is currently in progress.
            //
            // TODO: improve when support is available (see:
            // https://github.com/rust-lang/rust/issues/40032)
            libc::close(0);

            // Set the "sigint" flag
            sigint.store(true, Ordering::SeqCst);
        }).map_err(|_| "Unable to register SIGINT handler")?;

        signal_hook::register(signal_hook::SIGTERM, move || {
            libc::close(0);
            sigint2.store(true, Ordering::SeqCst);
        }).map_err(|_| "Unable to register SIGINT handler")?;
    }


    // Main tracing loop
    loop {
        // Check "sigint" flag: if set, kill the tracee process and break from the loop
        if sigint.load(Ordering::Relaxed) {
            println!("SIGINT received, killing tracee process...");
            if let Err(e) = signal::kill(tracee_pid, signal::Signal::SIGTERM) {
                println!("Unable to send SIGTERM to tracee process: {}", e);
            }
            if let Err(e) = signal::kill(tracee_pid, signal::Signal::SIGKILL) {
                println!("Unable to send SIGKILL to tracee process: {}", e);
            }
            break;
        }

        // Wait for any child process (-1)
        let wait_status = wait_child(Pid::from_raw(-1 as i32), false);
        if let Ok(ws) = wait_status {
            if let Err(s) = handle_wait_status(&ws) {
                println!("{}", s);
                break;
            }
        } else {
            println!("{:?}", wait_status);
            break;
        }

        // todo, original code waits for all childs
    }

    Ok(())
}

/// Executes a child process under ptrace using `execvp`.
///
/// Should be called by the tracer child process after forking.
///
/// # Arguments
///
///   - `cmd`: command argv for `execvp()` call
pub fn exec_child(cmd: Vec<&str>) -> Result<(), String> {
    ptrace::traceme()
        .map_err(|_| "CHILD: could not enable tracing by parent (PTRACE_TRACEME failed)")?;

    // Extract child command (first arg)
    let child_cmd = CString::new(*cmd.first().ok_or("Unable to extract tracee command")?)
        .map_err(|_| "Unable to extract tracee command")?;

    // Extract child arguments (including first command)
    let child_args = cmd
        .iter()
        .map(|v| CString::new(*v).unwrap_or_default())
        .collect::<Vec<CString>>();

    println!(
        "CHILD: executing {:?} with argv {:?}...",
        child_cmd, child_args
    );
    execvp(&child_cmd, &child_args).map_err(|e| format!("unable to execute {:?}: {}", child_cmd, e))?;
    Ok(())
}

fn main() -> Result<(), String> {
    let fork_res = unistd::fork().expect("could not fork");

    let cmd = vec!["ls", "-lah"];

    match fork_res {
        unistd::ForkResult::Parent { child } => {
            println!("Tracing child process {} ({:?})", child, cmd);

            // Wait for child and set trace options
            wait_child(child, false).expect("#1");
            ptrace::setoptions(
                child,
                ptrace::Options::PTRACE_O_EXITKILL

                    // Trace sub-processes of tracee
                    | ptrace::Options::PTRACE_O_TRACECLONE
                    | ptrace::Options::PTRACE_O_TRACEFORK
                    | ptrace::Options::PTRACE_O_TRACEVFORK
                    | ptrace::Options::PTRACE_O_TRACEVFORKDONE

                    | ptrace::Options::PTRACE_O_TRACEEXEC

                    // PTRACE_O_TRACESYSGOOD: recommended by strace README-linux-ptrace. Causes
                    // WaitStatus::PtraceSyscall to be generated instead of WaitStatus::Stopped
                    // upon syscall in tracee.
                    | ptrace::Options::PTRACE_O_TRACESYSGOOD,

                // PTRACE_O_TRACEEXIT will stop the tracee before exit in order to examine
                // registers. This is not required; without this option the tracer will be notified
                // after tracee exit.
                // ptrace::Options::PTRACE_O_TRACEEXIT
            )
                .map_err(|_| "Unable to set PTRACE_O_* options for child process")?;

            // Await next child syscall for main tracee
            ptrace::syscall(child)
                .map_err(|_| "Unable to set child process to run until first syscall")?;

            // Execute main child process control loop
            child_loop(child).expect("child loop");
        }
        unistd::ForkResult::Child => {
            exec_child(cmd).map_err(|_| "Unable to execute child process").expect("Unable to execute child process");
            // Ok(ProcessList::default())
        }
    };

    Ok(())

}
