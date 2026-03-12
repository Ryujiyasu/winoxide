//! Server-client Unix socket communication.
//!
//! Protocol:
//! - 1 fd-passing socket per process (SCM_RIGHTS for file descriptor transfer)
//! - 3 pipes per thread: request (client→server), reply (server→client), wait (server→client)
//! - All requests/replies are fixed 64-byte structs + optional variable-length data

use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

/// Maximum size of a request/reply fixed struct (16 x u32 = 64 bytes).
pub const MAX_REQUEST_SIZE: usize = 64;

/// Server protocol version — must match between client and server.
pub const SERVER_PROTOCOL_VERSION: u32 = 1;

/// Per-thread communication channels.
pub struct ThreadConnection {
    /// Client writes requests here (write end of pipe).
    pub request_fd: RawFd,
    /// Client reads replies here (read end of pipe).
    pub reply_fd: RawFd,
    /// Client reads async wake-ups here (read end of pipe).
    pub wait_fd: RawFd,
}

/// Server-side per-thread state.
pub struct ServerThread {
    /// Server reads requests from here (read end of request pipe).
    pub request_fd: RawFd,
    /// Server writes replies here (write end of reply pipe).
    pub reply_fd: RawFd,
    /// Server writes wake-ups here (write end of wait pipe).
    pub wait_fd: RawFd,
}

/// Per-process fd-passing socket (for SCM_RIGHTS).
pub struct ProcessConnection {
    pub fd_socket: UnixStream,
}

/// The server listener — accepts new process connections.
pub struct ServerListener {
    listener: UnixListener,
    socket_path: PathBuf,
}

impl ServerListener {
    /// Create and bind the server socket.
    pub fn bind(socket_dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(socket_dir)?;
        let socket_path = socket_dir.join("socket");

        // Remove stale socket
        let _ = std::fs::remove_file(&socket_path);

        let listener = UnixListener::bind(&socket_path)?;

        // Restrict permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(Self {
            listener,
            socket_path,
        })
    }

    /// Accept a new process connection.
    pub fn accept(&self) -> io::Result<ProcessConnection> {
        let (stream, _addr) = self.listener.accept()?;
        Ok(ProcessConnection { fd_socket: stream })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

impl Drop for ServerListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Create the 3 pipes for a new thread.
/// Returns (client_side, server_side).
pub fn create_thread_pipes() -> io::Result<(ThreadConnection, ServerThread)> {
    let (req_read, req_write) = pipe()?;
    let (reply_read, reply_write) = pipe()?;
    let (wait_read, wait_write) = pipe()?;

    Ok((
        ThreadConnection {
            request_fd: req_write,
            reply_fd: reply_read,
            wait_fd: wait_read,
        },
        ServerThread {
            request_fd: req_read,
            reply_fd: reply_write,
            wait_fd: wait_write,
        },
    ))
}

/// Create a pipe, returning (read_fd, write_fd).
fn pipe() -> io::Result<(RawFd, RawFd)> {
    let mut fds = [0i32; 2];
    let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok((fds[0], fds[1]))
    }
}

/// Send a fixed-size request over the request pipe.
pub fn send_request(fd: RawFd, buf: &[u8; MAX_REQUEST_SIZE]) -> io::Result<()> {
    let mut written = 0;
    while written < MAX_REQUEST_SIZE {
        let n = unsafe {
            libc::write(
                fd,
                buf[written..].as_ptr() as *const libc::c_void,
                MAX_REQUEST_SIZE - written,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        written += n as usize;
    }
    Ok(())
}

/// Send variable-length data after the fixed request.
pub fn send_vardata(fd: RawFd, data: &[u8]) -> io::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    let mut written = 0;
    while written < data.len() {
        let n = unsafe {
            libc::write(
                fd,
                data[written..].as_ptr() as *const libc::c_void,
                data.len() - written,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        written += n as usize;
    }
    Ok(())
}

/// Read a fixed-size reply from the reply pipe.
pub fn read_reply(fd: RawFd, buf: &mut [u8; MAX_REQUEST_SIZE]) -> io::Result<()> {
    let mut total = 0;
    while total < MAX_REQUEST_SIZE {
        let n = unsafe {
            libc::read(
                fd,
                buf[total..].as_mut_ptr() as *mut libc::c_void,
                MAX_REQUEST_SIZE - total,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "server disconnected"));
        }
        total += n as usize;
    }
    Ok(())
}

/// Read variable-length reply data.
pub fn read_vardata(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    let mut total = 0;
    while total < buf.len() {
        let n = unsafe {
            libc::read(
                fd,
                buf[total..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - total,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n == 0 {
            break;
        }
        total += n as usize;
    }
    Ok(total)
}

/// Send a file descriptor over the fd-passing socket using SCM_RIGHTS.
pub fn send_fd(socket: &UnixStream, fd: RawFd, tag: u32) -> io::Result<()> {
    let tag_bytes = tag.to_ne_bytes();

    let iov = libc::iovec {
        iov_base: tag_bytes.as_ptr() as *mut libc::c_void,
        iov_len: 4,
    };

    // Ancillary data buffer for one fd
    let mut cmsg_buf = [0u8; unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &iov as *const _ as *mut _;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len();

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize;
        std::ptr::copy_nonoverlapping(
            &fd as *const RawFd as *const u8,
            libc::CMSG_DATA(cmsg),
            std::mem::size_of::<RawFd>(),
        );
    }

    let ret = unsafe { libc::sendmsg(socket.as_raw_fd(), &msg, 0) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Receive a file descriptor from the fd-passing socket using SCM_RIGHTS.
/// Returns (fd, tag).
pub fn receive_fd(socket: &UnixStream) -> io::Result<(RawFd, u32)> {
    let mut tag_bytes = [0u8; 4];

    let mut iov = libc::iovec {
        iov_base: tag_bytes.as_mut_ptr() as *mut libc::c_void,
        iov_len: 4,
    };

    let mut cmsg_buf = [0u8; unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len();

    let ret = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msg, 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    if ret == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed"));
    }

    let tag = u32::from_ne_bytes(tag_bytes);

    // Extract the fd from ancillary data
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "no ancillary data"));
    }

    let mut fd: RawFd = -1;
    unsafe {
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(cmsg),
            &mut fd as *mut RawFd as *mut u8,
            std::mem::size_of::<RawFd>(),
        );
    }

    Ok((fd, tag))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn test_pipe_request_reply() {
        let (client, server) = create_thread_pipes().unwrap();

        // Client sends a request
        let mut req = [0u8; MAX_REQUEST_SIZE];
        req[0] = 42; // request code
        req[4] = 0xFF; // some data
        send_request(client.request_fd, &req).unwrap();

        // Server reads it
        let mut received = [0u8; MAX_REQUEST_SIZE];
        read_reply(server.request_fd, &mut received).unwrap();
        assert_eq!(received[0], 42);
        assert_eq!(received[4], 0xFF);

        // Server sends reply
        let mut reply = [0u8; MAX_REQUEST_SIZE];
        reply[0] = 0; // success
        send_request(server.reply_fd, &reply).unwrap();

        // Client reads reply
        let mut reply_buf = [0u8; MAX_REQUEST_SIZE];
        read_reply(client.reply_fd, &mut reply_buf).unwrap();
        assert_eq!(reply_buf[0], 0);

        // Cleanup
        unsafe {
            libc::close(client.request_fd);
            libc::close(client.reply_fd);
            libc::close(client.wait_fd);
            libc::close(server.request_fd);
            libc::close(server.reply_fd);
            libc::close(server.wait_fd);
        }
    }

    #[test]
    fn test_fd_passing() {
        let (sock_a, sock_b) = UnixStream::pair().unwrap();

        // Create a pipe, pass the read end
        let (read_fd, write_fd) = pipe().unwrap();

        // Send write_fd over the socket
        send_fd(&sock_a, write_fd, 0xDEAD).unwrap();

        // Receive it on the other side
        let (received_fd, tag) = receive_fd(&sock_b).unwrap();
        assert_eq!(tag, 0xDEAD);
        assert!(received_fd >= 0);

        // Write through the received fd, read from the original read end
        let msg = b"hello";
        unsafe {
            libc::write(received_fd, msg.as_ptr() as *const libc::c_void, msg.len());
        }
        let mut buf = [0u8; 5];
        unsafe {
            libc::read(read_fd, buf.as_mut_ptr() as *mut libc::c_void, 5);
        }
        assert_eq!(&buf, b"hello");

        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
            libc::close(received_fd);
        }
    }

    #[test]
    fn test_server_listener() {
        let dir = std::env::temp_dir().join("winoxide_test_server");
        let _ = std::fs::remove_dir_all(&dir);

        let server = ServerListener::bind(&dir).unwrap();
        let path = server.socket_path().to_path_buf();

        // Connect a client
        let _client = UnixStream::connect(&path).unwrap();
        let _conn = server.accept().unwrap();

        drop(server);
        assert!(!path.exists()); // cleaned up
        let _ = std::fs::remove_dir_all(&dir);
    }
}
