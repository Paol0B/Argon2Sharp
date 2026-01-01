use argon2::{
    Argon2, Algorithm, Version, ParamsBuilder, AssociatedData
};
use libc::{c_int, c_uchar, size_t};
use std::slice;

#[no_mangle]
pub extern "C" fn argon2_hash(
    password: *const c_uchar,
    password_len: size_t,
    salt: *const c_uchar,
    salt_len: size_t,
    secret: *const c_uchar,
    secret_len: size_t,
    ad: *const c_uchar,
    ad_len: size_t,
    iterations: c_int,
    memory_kb: c_int,
    parallelism: c_int,
    hash_len: c_int,
    type_code: c_int,
    version_code: c_int,
    output: *mut c_uchar,
) -> c_int {
    if password.is_null() || salt.is_null() || output.is_null() {
        return -1;
    }

    let password_slice = unsafe { slice::from_raw_parts(password, password_len) };
    let salt_slice = unsafe { slice::from_raw_parts(salt, salt_len) };
    
    let secret_slice = if !secret.is_null() && secret_len > 0 {
        unsafe { slice::from_raw_parts(secret, secret_len) }
    } else {
        &[]
    };

    let ad_slice = if !ad.is_null() && ad_len > 0 {
        unsafe { slice::from_raw_parts(ad, ad_len) }
    } else {
        &[]
    };

    let algorithm = match type_code {
        0 => Algorithm::Argon2d,
        1 => Algorithm::Argon2i,
        2 => Algorithm::Argon2id,
        _ => return -2,
    };

    let version = match version_code {
        0x10 => Version::V0x10,
        0x13 => Version::V0x13,
        _ => return -3,
    };

    let mut params_builder = ParamsBuilder::new();
    params_builder
        .m_cost(memory_kb as u32)
        .t_cost(iterations as u32)
        .p_cost(parallelism as u32)
        .output_len(hash_len as usize);

    if !ad_slice.is_empty() {
        let ad = match AssociatedData::new(ad_slice) {
            Ok(ad) => ad,
            Err(_) => return -4,
        };
        params_builder.data(ad);
    }

    let params = match params_builder.build() {
        Ok(p) => p,
        Err(_) => return -5,
    };

    let argon2 = match Argon2::new_with_secret(secret_slice, algorithm, version, params) {
        Ok(a) => a,
        Err(_) => return -6,
    };

    let output_slice = unsafe { slice::from_raw_parts_mut(output, hash_len as usize) };

    match argon2.hash_password_into(password_slice, salt_slice, output_slice) {
        Ok(_) => 0,
        Err(_) => -7,
    }
}
