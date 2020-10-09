use nix::fcntl::OFlag;
use nix::unistd::Pid;
use nix::sys::uio;

pub fn get_child_buffer_cstr(pid: Pid, base: usize) -> Result<String, &'static str> {
    let mut final_buf: Vec<u8> = Vec::with_capacity(255);

    // Current RemoteIoVec base address
    let mut current_base = base;

    // Index of 0 byte in final_buf
    let mut nul_idx: isize = -1;

    // Keep reading 255-byte chunks from the process VM until one contains a 0 byte
    // (null-termination character)
    loop {
        // Read into a temporary buffer
        let mut rbuf: Vec<u8> = vec![0; 255];
        let remote_iovec = uio::RemoteIoVec {
            base: current_base,
            len: 255,
        };
        uio::process_vm_readv(
            pid,
            &[uio::IoVec::from_mut_slice(rbuf.as_mut_slice())],
            &[remote_iovec],
        )
            .map_err(|_| "Unable to read from child process virtual memory")?;

        // Append temporary buffer to the final buffer and increase base address pointer
        final_buf.append(&mut rbuf);
        current_base += 255;

        // If final_buf contains a 0 byte, store the index and break from the read loop
        if final_buf.contains(&0) {
            if let Some(idx) = final_buf.iter().position(|&x| x == 0) {
                nul_idx = idx as isize;
            }
            break;
        }
    }
    if nul_idx > -1 {
        Ok(String::from_utf8_lossy(&final_buf[0..(nul_idx as usize)]).into_owned())
    } else {
        Err("Null-terminated string not found")
    }
}

pub struct SyscallEntry {
    handled: bool,
    description: String,
}

impl SyscallEntry {

    pub fn new(
        handled: bool,
        description: String
    ) -> SyscallEntry {
        Self {
            handled,
            description
        }
    }

    pub fn get_description(&self) -> &str {
        &self.description
    }

    pub fn new_pre(
        pid: Pid,
        regs: &::libc::user_regs_struct,
        syscall_id : u32
    ) -> SyscallEntry {
        match syscall_id {
            // read
            0 => {
                SyscallEntry::new(
                    true,
                    format!(
                        "Child process {} will read {} bytes from FD {} into buffer at 0x{:X}\n - File: #{:?}",
                        pid, regs.rdx, regs.rdi, regs.rsi, regs.rdi as usize //state.file_by_fd(regs.rdi as usize)
                    ),
                )
            }

            // write
            1 => {
                SyscallEntry::new(
                    true,
                    format!(
                        "Child process {} will write {} bytes to FD {} from buffer at 0x{:X}",
                        pid, regs.rdx, regs.rdi, regs.rsi
                    ),
                )
            }

            // open
            2 => {
                let mut desc = format!(
                    "Child process {} will open a file with flags {:?} and mode {:?}",
                    pid,
                    OFlag::from_bits(regs.rsi as libc::c_int),
                    OFlag::from_bits(regs.rdx as libc::c_int),
                );
                match get_child_buffer_cstr(pid, regs.rdi as usize) {
                    Ok(filepath) => {
                        desc = format!("{}\n{}", desc, format!(" - File path: {:?}", filepath));
                    }
                    Err(e) => {
                        desc = format!("{}\n{}", desc, format!(" - Could not get file path: {}", e));
                    }
                };
                SyscallEntry::new(true, desc)
            }

            // close
            3 => {
                let mut desc = format!("Child process {} wants to close FD {}", pid, regs.rdi);
                SyscallEntry::new(true, desc)
            }

            /*
            // socket
            41 => {
                SyscallEntry::new(true, sockets::handle_socket_pre(state, regs, pid))
            }

            // connect
            42 => {
                SyscallEntry::new(true, sockets::handle_connect_pre(state, regs, pid))
            }
             */

            // openat
            257 => {
                let mut desc = format!(
                    "Child process {} will open a file with flags {:?} and mode {:?} at dirfd {}",
                    pid,
                    OFlag::from_bits(regs.rdx as libc::c_int),
                    OFlag::from_bits(regs.r10 as libc::c_int),
                    regs.rdi,
                );
                match get_child_buffer_cstr(pid, regs.rsi as usize) {
                    Ok(filepath) => {
                        desc = format!("{}\n{}", desc, format!(" - File path: {:?}", filepath));
                    }
                    Err(e) => {
                        desc = format!("{}\n{}", desc, format!(" - Could not get file path: {}", e));
                    }
                };
                SyscallEntry::new(true, desc)
            }
            _ => {
                SyscallEntry::new(
                    false,
                    format!(
                        "Unhandled syscall {:?} ({:X}, {:X}, {:X}, {:X}, {:X}, {:X})",
                        syscall_id,
                        regs.rdi,
                        regs.rsi,
                        regs.rdx,
                        regs.r10,
                        regs.r8,
                        regs.r9
                    ),
                )
            },
        }
    }
}