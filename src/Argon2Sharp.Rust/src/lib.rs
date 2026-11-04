use argon2::{Algorithm, Argon2, AssociatedData, Block, ParamsBuilder, Version};
use blake2::{Blake2b256, Digest};
use std::panic::{self, AssertUnwindSafe};
use std::ptr::NonNull;
use std::{mem, slice};

/// # Safety
/// Each pointer must be null or valid for its length; `output` must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn argon2_hash(
    pass: *const u8,
    pass_len: usize,
    salt: *const u8,
    salt_len: usize,
    secret: *const u8,
    secret_len: usize,
    ad: *const u8,
    ad_len: usize,
    t_cost: u32,
    m_cost: u32,
    p_cost: u32,
    output: *mut u8,
    output_len: usize,
    type_val: u32,
    version_val: u32,
) -> u32 {
    // a panic must not unwind into the .NET caller: that aborts the process
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        if output.is_null() {
            return 1;
        }
        let (Some(pass_slice), Some(salt_slice), Some(secret_slice), Some(ad_slice)) = (unsafe {
            (
                input(pass, pass_len),
                input(salt, salt_len),
                input(secret, secret_len),
                input(ad, ad_len),
            )
        }) else {
            return 1;
        };
        let output_slice = unsafe { slice::from_raw_parts_mut(output, output_len) };

        // The RustCrypto `argon2` crate currently limits associated data to 32 bytes.
        // Argon2 (RFC 9106) permits much larger associated data, and Argon2Sharp's API/tests
        // exercise that. To remain plug-and-play while using this crate, we compress larger
        // associated data to 32 bytes via Blake2b-256.
        let ad_compact;
        let ad_for_params: &[u8] = if ad_slice.len() > AssociatedData::MAX_LEN {
            ad_compact = Blake2b256::digest(ad_slice);
            &ad_compact
        } else {
            ad_slice
        };

        // Map algorithm type
        let algorithm = match type_val {
            0 => Algorithm::Argon2d,
            1 => Algorithm::Argon2i,
            2 => Algorithm::Argon2id,
            _ => return 2, // Invalid algorithm
        };

        // Map version
        let version = match version_val {
            0x10 => Version::V0x10,
            0x13 => Version::V0x13,
            _ => return 3, // Invalid version
        };

        // Build params
        let mut params_builder = ParamsBuilder::new();
        params_builder
            .m_cost(m_cost)
            .t_cost(t_cost)
            .p_cost(p_cost)
            .output_len(output_len);

        // Set associated data if present
        if !ad_for_params.is_empty() {
            match AssociatedData::new(ad_for_params) {
                Ok(ad_obj) => {
                    params_builder.data(ad_obj);
                }
                Err(_) => return 4, // Invalid associated data
            }
        }

        let params = match params_builder.build() {
            Ok(p) => p,
            Err(_) => return 5, // Invalid params
        };

        // Create Argon2 context with secret
        let argon2 = match Argon2::new_with_secret(secret_slice, algorithm, version, params) {
            Ok(a) => a,
            Err(_) => return 6, // Failed to create context
        };

        let Some(mut memory) = BlockMemory::new(argon2.params().block_count()) else {
            return 8; // Out of memory
        };

        // Perform hashing
        match argon2.hash_password_into_with_memory(
            pass_slice,
            salt_slice,
            output_slice,
            memory.blocks(),
        ) {
            Ok(_) => 0,  // Success
            Err(_) => 7, // Hashing failed
        }
    }));
    result.unwrap_or(9) // Panic
}

unsafe fn input<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        Some(&[])
    } else if ptr.is_null() {
        None
    } else {
        Some(unsafe { slice::from_raw_parts(ptr, len) })
    }
}

/// Argon2 working memory mapped from the OS and unmapped after each hash.
/// The C heap would keep it: glibc retains freed blocks of this size in its arenas.
struct BlockMemory {
    base: NonNull<u8>,
    mapped: usize,
    blocks: NonNull<Block>,
    len: usize,
}

// mappings are page-aligned
const _: () = assert!(mem::align_of::<Block>() <= 4096);

impl BlockMemory {
    fn new(len: usize) -> Option<Self> {
        let size = len.checked_mul(mem::size_of::<Block>())?;
        if size == 0 {
            return None;
        }
        let (base, mapped, start) = os::map(size)?;
        Some(Self {
            base,
            mapped,
            blocks: start.cast(),
            len,
        })
    }

    fn blocks(&mut self) -> &mut [Block] {
        unsafe { slice::from_raw_parts_mut(self.blocks.as_ptr(), self.len) }
    }
}

impl Drop for BlockMemory {
    fn drop(&mut self) {
        // no wipe: unmapped pages leave the process and the kernel zeroes them before any reuse;
        // a wipe would add about 10% to each hash
        unsafe { os::unmap(self.base, self.mapped) };
    }
}

#[cfg(unix)]
mod os {
    use std::ptr::{self, NonNull};

    #[cfg(target_os = "linux")]
    const HUGE_PAGE: usize = 2 << 20;

    /// Returns the mapping base, the mapped length and the start of `size` usable bytes.
    pub fn map(size: usize) -> Option<(NonNull<u8>, usize, NonNull<u8>)> {
        // fresh 4 KiB pages fault one by one; a 2 MiB-aligned start lets Linux back them with
        // transparent huge pages, which removes most of that cost
        #[cfg(target_os = "linux")]
        let mapped = if size >= HUGE_PAGE {
            size.checked_add(HUGE_PAGE)?
        } else {
            size
        };
        #[cfg(not(target_os = "linux"))]
        let mapped = size;

        let addr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                mapped,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            return None;
        }
        let base = NonNull::new(addr.cast::<u8>())?;

        #[cfg(target_os = "linux")]
        if mapped > size {
            let start = unsafe { base.add(base.align_offset(HUGE_PAGE)) };
            // fails harmlessly when THP is disabled
            unsafe { libc::madvise(start.as_ptr().cast(), size, libc::MADV_HUGEPAGE) };
            return Some((base, mapped, start));
        }
        Some((base, mapped, base))
    }

    /// # Safety
    /// `base` and `len` must come from one `map` call.
    pub unsafe fn unmap(base: NonNull<u8>, len: usize) {
        unsafe { libc::munmap(base.as_ptr().cast(), len) };
    }
}

#[cfg(windows)]
mod os {
    use std::ffi::c_void;
    use std::ptr::{self, NonNull};

    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const MEM_RELEASE: u32 = 0x8000;
    const PAGE_READWRITE: u32 = 0x04;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn VirtualAlloc(address: *mut c_void, size: usize, kind: u32, protect: u32) -> *mut c_void;
        fn VirtualFree(address: *mut c_void, size: usize, kind: u32) -> i32;
    }

    /// Returns the mapping base, the mapped length and the start of `size` usable bytes.
    pub fn map(size: usize) -> Option<(NonNull<u8>, usize, NonNull<u8>)> {
        let addr = unsafe {
            VirtualAlloc(
                ptr::null_mut(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        let base = NonNull::new(addr.cast::<u8>())?;
        Some((base, size, base))
    }

    /// # Safety
    /// `base` must come from a `map` call.
    pub unsafe fn unmap(base: NonNull<u8>, _len: usize) {
        unsafe { VirtualFree(base.as_ptr().cast(), 0, MEM_RELEASE) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(algorithm: u32) -> [u8; 32] {
        let (pass, salt, secret, ad) = ([1u8; 32], [2u8; 16], [3u8; 8], [4u8; 12]);
        let mut out = [0u8; 32];
        let rc = unsafe {
            argon2_hash(
                pass.as_ptr(),
                pass.len(),
                salt.as_ptr(),
                salt.len(),
                secret.as_ptr(),
                secret.len(),
                ad.as_ptr(),
                ad.len(),
                3,
                32,
                4,
                out.as_mut_ptr(),
                out.len(),
                algorithm,
                0x13,
            )
        };
        assert_eq!(rc, 0);
        out
    }

    #[test]
    fn rfc9106_vectors() {
        let expected = [
            "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
            "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
        ];
        for (algorithm, hex) in expected.iter().enumerate() {
            let actual: String = hash(algorithm as u32)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(&actual, hex, "algorithm {algorithm}");
        }
    }

    #[test]
    fn memory_is_zeroed_and_aligned() {
        for len in [8, 19456] {
            let mut memory = BlockMemory::new(len).unwrap();
            let blocks = memory.blocks();
            assert_eq!(blocks.len(), len);
            assert_eq!(blocks.as_ptr().align_offset(mem::align_of::<Block>()), 0);
            assert!(blocks.iter().all(|b| b.as_ref().iter().all(|&w| w == 0)));
        }
    }
}
