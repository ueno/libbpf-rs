//! Dump btf information.

use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::io;
use std::mem;
use std::os::raw::c_char;
use std::os::raw::c_void;
use std::ptr::NonNull;
use std::result;

use crate::btf::Btf;
use crate::btf::TypeId;
use crate::object::AsRawLibbpf;
use crate::util::parse_ret_i32;
use crate::util::validate_bpf_ret;
use crate::ErrorExt as _;
use crate::Result;

type WriteCb<'btf> = Box<dyn FnMut(&[u8]) -> result::Result<usize, io::Error> + 'btf>;

struct CbStruct<'btf> {
    write_cb: WriteCb<'btf>,
    result: Option<result::Result<usize, io::Error>>,
}

impl Debug for CbStruct<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Self { write_cb, result } = self;
        f.debug_struct("CbStruct")
            .field("write_cb", &(&write_cb as *const _))
            .field("result", &result)
            .finish()
    }
}

unsafe extern "C" fn call_write_cb(
    ctx: *mut c_void,
    fmtstr: *const c_char,
    // bindgen generated va_list type varies on different platforms, so just use void pointer
    // instead. It's safe because this argument is always a pointer.
    // The pointer of this function would be transmuted and passing to BtfDump::new below.
    // See <https://github.com/rust-lang/rust-bindgen/issues/2631>
    va_list: *mut c_void,
) {
    let callback_struct = ctx.cast::<CbStruct<'_>>();

    let cb = unsafe { &mut (*callback_struct).write_cb };
    if let Ok(slice) = unsafe { vsprintf::vsprintf(fmtstr, va_list) } {
        let result = cb(slice.as_bytes());
        unsafe { (*callback_struct).result = Some(result) };
    }
}

/// Dump btf information.
#[doc(alias = "btf_dump")]
#[derive(Debug)]
pub struct BtfDump<'btf> {
    ptr: NonNull<libbpf_sys::btf_dump>,
    callback_struct: Box<CbStruct<'btf>>,
}

impl<'btf> BtfDump<'btf> {
    /// Create a new btf dump.
    #[doc(alias = "btf_dump__new")]
    pub fn new<F>(btf: &'btf Btf, write_cb: F) -> Result<Self>
    where
        F: FnMut(&[u8]) -> result::Result<usize, io::Error> + 'btf,
    {
        let opts = libbpf_sys::btf_dump_opts {
            sz: size_of::<libbpf_sys::btf_dump_opts>() as _,
        };

        // # Safety
        // outer_print_cb has the same function signature as btf_dump_print_fn_t
        #[expect(clippy::missing_transmute_annotations)]
        let real_call_write_cb: libbpf_sys::btf_dump_printf_fn_t =
            unsafe { Some(mem::transmute(call_write_cb as *const ())) };

        let callback_struct_ptr = Box::into_raw(Box::new(CbStruct {
            write_cb: Box::new(write_cb),
            result: None,
        }));

        let ptr = unsafe {
            libbpf_sys::btf_dump__new(
                btf.as_libbpf_object().as_ptr(),
                real_call_write_cb,
                callback_struct_ptr.cast(),
                &opts,
            )
        };

        let ptr = validate_bpf_ret(ptr).context("failed to create BTF dump")?;

        Ok(Self {
            ptr,
            callback_struct: unsafe { Box::from_raw(callback_struct_ptr) },
        })
    }

    /// Dump a btf type given by [`TypeId`].
    ///
    /// Returns the number of bytes written.
    #[doc(alias = "btf_dump__dump_type")]
    pub fn dump_type(&mut self, type_id: TypeId) -> Result<usize> {
        parse_ret_i32(unsafe {
            libbpf_sys::btf_dump__dump_type(self.ptr.as_ptr(), type_id.into())
        })?;
        self.callback_struct
            .result
            .take()
            .unwrap_or_else(|| Err(io::Error::other("write callback never called")))
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btf::types;

    #[test]
    fn dump_type() {
        let btf = Btf::from_vmlinux().expect("failed to extract btf information from vmlinux");
        let ty = btf
            .type_by_kind::<types::Typedef<'_>>()
            .next()
            .expect("failed to extract first typedef");
        let mut dump =
            BtfDump::new(&btf, |slice: &[u8]| Ok(slice.len())).expect("failed to create btf dump");
        let written = dump.dump_type(ty.type_id()).expect("failed to dump type");
        assert!(written > 0);
    }
}
