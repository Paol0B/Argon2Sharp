use argon2::{Algorithm, Argon2, AssociatedData, Block, ParamsBuilder, Version};
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use std::alloc::Layout;
use std::mem;
use std::ptr::{self, NonNull};
use std::slice;
use std::sync::atomic::{compiler_fence, Ordering};

/// # Safety
/// Each non-null pointer must be valid for its length.
#[no_mangle]
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
    // Safety checks for pointers
    if output.is_null() {
        return 1;
    }
    if pass.is_null() && pass_len != 0 {
        return 1;
    }
    if salt.is_null() && salt_len != 0 {
        return 1;
    }
    if secret.is_null() && secret_len != 0 {
        return 1;
    }
    if ad.is_null() && ad_len != 0 {
        return 1;
    }

    // Convert raw pointers to slices
    let pass_slice = if pass_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(pass, pass_len) }
    };

    let salt_slice = if salt_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(salt, salt_len) }
    };

    let output_slice = unsafe { slice::from_raw_parts_mut(output, output_len) };

    // Handle optional secret
    let secret_slice = if secret_len > 0 {
        unsafe { slice::from_raw_parts(secret, secret_len) }
    } else {
        &[]
    };

    // Handle optional associated data
    let ad_slice = if ad_len > 0 {
        unsafe { slice::from_raw_parts(ad, ad_len) }
    } else {
        &[]
    };

    // The RustCrypto `argon2` crate currently limits associated data to 32 bytes.
    // Argon2 (RFC 9106) permits much larger associated data, and Argon2Sharp's API/tests
    // exercise that. To remain plug-and-play while using this crate, we compress larger
    // associated data to 32 bytes via Blake2b-256.
    let mut ad_compact = [0u8; 32];
    let ad_for_params: &[u8] = if ad_slice.len() > 32 {
        let mut hasher = match Blake2bVar::new(32) {
            Ok(h) => h,
            Err(_) => return 4,
        };
        hasher.update(ad_slice);
        if hasher.finalize_variable(&mut ad_compact).is_err() {
            return 4;
        }
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

    // Map the working memory from the OS so it is released after each hash (#14)
    let mut memory = match BlockMemory::new(argon2.params().block_count()) {
        Some(m) => m,
        None => return 8, // Failed to allocate memory
    };

    // Perform hashing
    match argon2.hash_password_into_with_memory(pass_slice, salt_slice, output_slice, &mut memory) {
        Ok(_) => 0,  // Success
        Err(_) => 7, // Hashing failed
    }
}

/// Argon2 blocks mapped from the OS, wiped and unmapped on drop.
struct BlockMemory {
    blocks: NonNull<Block>,
    len: usize,
}

// Mappings are page-aligned
const _: () = assert!(mem::align_of::<Block>() <= 4096);

impl BlockMemory {
    fn new(len: usize) -> Option<Self> {
        let size = Layout::array::<Block>(len).ok()?.size();
        if size == 0 {
            return None;
        }
        let base = unsafe { os::map(size) }?;
        Some(Self {
            blocks: base.cast(),
            len,
        })
    }

    fn size(&self) -> usize {
        self.len * mem::size_of::<Block>()
    }

    fn wipe(&mut self) {
        let words = self.blocks.as_ptr().cast::<u64>();
        for i in 0..self.size() / mem::size_of::<u64>() {
            unsafe { ptr::write_volatile(words.add(i), 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl AsMut<[Block]> for BlockMemory {
    fn as_mut(&mut self) -> &mut [Block] {
        unsafe { slice::from_raw_parts_mut(self.blocks.as_ptr(), self.len) }
    }
}

impl Drop for BlockMemory {
    fn drop(&mut self) {
        // The blocks are derived from the password
        self.wipe();
        unsafe { os::unmap(self.blocks.cast(), self.size()) };
    }
}

#[cfg(unix)]
mod os {
    use std::ptr::{self, NonNull};

    pub unsafe fn map(size: usize) -> Option<NonNull<u8>> {
        let addr = libc::mmap(
            ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if addr == libc::MAP_FAILED {
            return None;
        }
        NonNull::new(addr.cast())
    }

    pub unsafe fn unmap(addr: NonNull<u8>, size: usize) {
        libc::munmap(addr.as_ptr().cast(), size);
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
    extern "system" {
        fn VirtualAlloc(address: *mut c_void, size: usize, kind: u32, protect: u32) -> *mut c_void;
        fn VirtualFree(address: *mut c_void, size: usize, kind: u32) -> i32;
    }

    pub unsafe fn map(size: usize) -> Option<NonNull<u8>> {
        let addr = VirtualAlloc(
            ptr::null_mut(),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        NonNull::new(addr.cast())
    }

    pub unsafe fn unmap(addr: NonNull<u8>, _size: usize) {
        VirtualFree(addr.as_ptr().cast(), 0, MEM_RELEASE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write;

    struct Case<'a> {
        algorithm: Algorithm,
        version: Version,
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
        pass: &'a [u8],
        salt: &'a [u8],
        secret: &'a [u8],
        ad: &'a [u8],
    }

    impl Case<'_> {
        fn ffi(&self) -> Vec<u8> {
            let mut out = vec![0u8; 32];
            let rc = unsafe {
                argon2_hash(
                    self.pass.as_ptr(),
                    self.pass.len(),
                    self.salt.as_ptr(),
                    self.salt.len(),
                    self.secret.as_ptr(),
                    self.secret.len(),
                    self.ad.as_ptr(),
                    self.ad.len(),
                    self.t_cost,
                    self.m_cost,
                    self.p_cost,
                    out.as_mut_ptr(),
                    out.len(),
                    self.algorithm as u32,
                    self.version as u32,
                )
            };
            assert_eq!(rc, 0);
            out
        }

        // Memory allocated by the argon2 crate, as before the fix
        fn reference(&self) -> Vec<u8> {
            let mut builder = ParamsBuilder::new();
            builder
                .m_cost(self.m_cost)
                .t_cost(self.t_cost)
                .p_cost(self.p_cost)
                .output_len(32);
            if !self.ad.is_empty() {
                builder.data(AssociatedData::new(self.ad).unwrap());
            }
            let params = builder.build().unwrap();
            let argon2 =
                Argon2::new_with_secret(self.secret, self.algorithm, self.version, params).unwrap();
            let mut out = vec![0u8; 32];
            argon2
                .hash_password_into(self.pass, self.salt, &mut out)
                .unwrap();
            out
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    #[test]
    fn rfc9106_test_vectors() {
        let vectors = [
            (
                Algorithm::Argon2d,
                "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
            ),
            (
                Algorithm::Argon2i,
                "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
            ),
            (
                Algorithm::Argon2id,
                "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
            ),
        ];
        for (algorithm, expected) in vectors {
            let case = Case {
                algorithm,
                version: Version::V0x13,
                m_cost: 32,
                t_cost: 3,
                p_cost: 4,
                pass: &[0x01; 32],
                salt: &[0x02; 16],
                secret: &[0x03; 8],
                ad: &[0x04; 12],
            };
            assert_eq!(hex(&case.ffi()), expected, "{algorithm:?}");
        }
    }

    #[test]
    fn default_parameters_match_reference_implementation() {
        let case = Case {
            algorithm: Algorithm::Argon2id,
            version: Version::V0x13,
            m_cost: 19456,
            t_cost: 2,
            p_cost: 1,
            pass: b"correct horse battery staple",
            salt: b"somesalt",
            secret: &[],
            ad: &[],
        };
        // phc-winner-argon2 CLI output
        assert_eq!(
            hex(&case.ffi()),
            "0448030d65fba6008da377dd849f43ea3859c7fee13d43cd45acb3060e4b1d13"
        );
    }

    #[test]
    fn output_matches_crate_allocated_memory() {
        let shapes = [(8, 1, 1), (19, 2, 1), (64, 3, 4), (100, 2, 3), (1024, 1, 2)];
        let keys: [(&[u8], &[u8]); 2] = [(b"", b""), (b"pepper", b"context")];
        for algorithm in [Algorithm::Argon2d, Algorithm::Argon2i, Algorithm::Argon2id] {
            for version in [Version::V0x10, Version::V0x13] {
                for (m_cost, t_cost, p_cost) in shapes {
                    for (secret, ad) in keys {
                        let case = Case {
                            algorithm,
                            version,
                            m_cost,
                            t_cost,
                            p_cost,
                            pass: b"password",
                            salt: b"somesalt",
                            secret,
                            ad,
                        };
                        assert_eq!(
                            case.ffi(),
                            case.reference(),
                            "{algorithm:?} {version:?} m={m_cost} t={t_cost} p={p_cost}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn block_memory_is_zeroed_and_aligned() {
        let mut memory = BlockMemory::new(19).expect("mapping failed");
        let blocks = memory.as_mut();
        assert_eq!(blocks.len(), 19);
        assert_eq!(blocks.as_ptr() as usize % mem::align_of::<Block>(), 0);
        assert!(blocks.iter().all(|b| b.as_ref().iter().all(|&w| w == 0)));
    }

    #[test]
    fn wipe_clears_every_block() {
        let mut memory = BlockMemory::new(19).expect("mapping failed");
        for block in memory.as_mut() {
            block.as_mut().fill(u64::MAX);
        }
        memory.wipe();
        assert!(memory
            .as_mut()
            .iter()
            .all(|b| b.as_ref().iter().all(|&w| w == 0)));
    }

    #[test]
    fn rejects_sizes_that_cannot_be_mapped() {
        assert!(BlockMemory::new(0).is_none());
        assert!(BlockMemory::new(usize::MAX).is_none());
        // Valid size, but larger than any address space: the OS refuses the mapping
        assert!(BlockMemory::new(isize::MAX as usize / mem::size_of::<Block>()).is_none());
    }
}
