use argon2::{Argon2, Algorithm, AssociatedData, ParamsBuilder, Version};
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use std::slice;

#[no_mangle]
pub extern "C" fn argon2_hash(
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
            },
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

    // Perform hashing
    match argon2.hash_password_into(pass_slice, salt_slice, output_slice) {
        Ok(_) => 0, // Success
        Err(_) => 7, // Hashing failed
    }
}
