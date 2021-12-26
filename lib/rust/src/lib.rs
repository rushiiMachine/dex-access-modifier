use std::{fs, panic};
use std::any::type_name;
use std::ptr::slice_from_raw_parts;
use std::time::SystemTime;

use adler32::RollingAdler32;
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jobjectArray;
use log::{debug, info, warn};

use crate::structures::structures::{ClassDefItem, DexFileHeader};
use crate::uleb128::uleb128::{read_uleb128, write_uleb128};

mod uleb128;
mod structures;

#[no_mangle]
pub extern "system" fn Java_com_github_diamondminer88_dexaccessmodifier_DexAccessModifier_init(
    env: JNIEnv,
    _class: JClass,
    log_level: JString,
) {
    android_logd_logger::builder()
        .parse_filters(env.get_string(log_level).unwrap().to_str().unwrap())
        .prepend_module(false)
        .init();
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_github_diamondminer88_dexaccessmodifier_DexAccessModifier_run(env: JNIEnv, _class: JClass, input_path_: JString, output_path_: JString, class_filters_: jobjectArray) {
    let input_path: String = env.get_string(input_path_).unwrap().into();
    let output_path: String = env.get_string(output_path_).unwrap().into();

    let mut class_filters = vec![];
    for i in 0..(env.get_array_length(class_filters_).unwrap()) {
        let elem: JString = env.get_object_array_element(class_filters_, i).unwrap().into();
        let filter: String = env.get_string(elem).unwrap().into();
        class_filters.push(filter);
    }

    let bytes = match fs::read(input_path.clone()) {
        Ok(data) => data,
        Err(err) => {
            env.throw(format!("Failed to read file: {0}", err.to_string())).unwrap();
            return;
        }
    };

    let now = SystemTime::now();
    let result = panic::catch_unwind(|| { modify_dex(&bytes, class_filters) });
    if let Err(panic) = result {
        let err_str = match panic.downcast::<String>() {
            Ok(err) => *err,
            // TODO: fix error printing
            Err(err) => format!("panic with unknown error: {0}", type_of(&err)),
        };
        env.throw(err_str).unwrap();
        return;
    }
    info!("Modified file {0} in {1}ms", input_path, now.elapsed().unwrap().as_millis());

    match fs::write(output_path, &bytes) {
        Err(err) => {
            env.throw(format!("Failed to write to file: {0}", err.to_string())).unwrap();
        }
        _ => {}
    }
}

#[allow(unaligned_references)]
unsafe fn modify_dex(bytes: &Vec<u8>, class_filters: Vec<String>) {
    let header = ptr_to_struct_with_offset::<DexFileHeader>(bytes.as_ptr(), 0);

    if header.endian_tag != endian_constants::LITTLE_ENDIAN {
        panic!("cannot handle big endian dex files");
    }

    if header.class_defs_offset == 0 { return; } // no class defs

    let mut ignored_type_id_idxs = vec![];
    if !class_filters.is_empty() && header.string_ids_offset != 0 && header.type_ids_offset != 0 {
        for type_id_idx in 0..(header.type_ids_size) {
            let type_id = *(u32_ptr_offset(bytes.as_ptr(), header.type_ids_offset + type_id_idx * 4) as *const u32);
            let string_data_offset = *(u32_ptr_offset(bytes.as_ptr(), header.string_ids_offset + type_id * 4) as *const u32);

            let string_length_uleb = read_uleb128(bytes.as_ptr(), string_data_offset).unwrap();
            let string_data = &*slice_from_raw_parts(u32_ptr_offset(bytes.as_ptr(), string_data_offset + string_length_uleb.length as u32), string_length_uleb.value as usize);
            for filter in class_filters.iter() {
                if string_data.starts_with(filter.as_bytes()) {
                    ignored_type_id_idxs.push(type_id_idx);
                }
            }
        }
    }

    debug!("Ignored type ids: {:?}", ignored_type_id_idxs);

    let class_defs_ptr = u32_ptr_offset(bytes.as_ptr(), header.class_defs_offset);
    for class_def_idx in 0..(header.class_defs_size) {
        let class_def = ptr_to_struct_with_offset::<ClassDefItem>(class_defs_ptr, 0x20 * class_def_idx);
        if ignored_type_id_idxs.contains(&class_def.class_idx) { continue; } // Class ignored
        class_def.access_flags = update_access_flags(class_def.access_flags);

        debug!("Parsing class at offset: {:#04x}", class_def.class_data_offset);
        if class_def.class_data_offset == 0 { continue; } // no data for this class

        let class_data_ptr = u32_ptr_offset(bytes.as_ptr(), class_def.class_data_offset);
        let mut offset = 0u32;

        let static_fields_size = read_uleb128(class_data_ptr, offset).unwrap();
        offset += static_fields_size.length as u32;
        let instance_fields_size = read_uleb128(class_data_ptr, offset).unwrap();
        offset += instance_fields_size.length as u32;
        let direct_methods_size = read_uleb128(class_data_ptr, offset).unwrap();
        offset += direct_methods_size.length as u32;
        let virtual_methods_size = read_uleb128(class_data_ptr, offset).unwrap();
        offset += virtual_methods_size.length as u32;

        debug!("Static fields: {0}, Instance fields: {1}, Direct methods: {2}, Virtual methods: {3}", static_fields_size.value, instance_fields_size.value, direct_methods_size.value, virtual_methods_size.value);

        for _ in 0..(static_fields_size.value + instance_fields_size.value) {
            let field_idx_diff = read_uleb128(class_data_ptr, offset).unwrap();
            offset += field_idx_diff.length as u32;

            let access_flags_length = update_access_flags_uleb128(u32_ptr_offset(class_data_ptr, offset), false);
            offset += access_flags_length as u32;
        }

        for _ in 0..(direct_methods_size.value + virtual_methods_size.value) {
            let method_idx_diff = read_uleb128(class_data_ptr, offset).unwrap();
            offset += method_idx_diff.length as u32;

            let access_flags_length = update_access_flags_uleb128(u32_ptr_offset(class_data_ptr, offset), true);
            offset += access_flags_length as u32;

            let code_off = read_uleb128(class_data_ptr, offset).unwrap();
            offset += code_off.length as u32;
        }
    }

    let mut hasher = sha1::Sha1::new();
    hasher.update(&bytes[32..]);
    header.signature = hasher.digest().bytes();

    header.checksum = RollingAdler32::from_buffer(&bytes[12..]).hash();
}

fn type_of<T>(_: T) -> &'static str { type_name::<T>() }

fn update_access_flags(access_flags: u32) -> u32 {
    return (access_flags & !(access_flags::ACC_PRIVATE | access_flags::ACC_PROTECTED)) | access_flags::ACC_PUBLIC;
}

// returns access_flags length to be used as a further offset
unsafe fn update_access_flags_uleb128(ptr: *mut u8, is_method: bool) -> u8 {
    let access_flags = read_uleb128(ptr, 0).unwrap();

    // skip private instance methods
    if is_method && access_flags.value & (access_flags::ACC_STATIC | access_flags::ACC_CONSTRUCTOR | access_flags::ACC_PRIVATE) == access_flags::ACC_PRIVATE { return access_flags.length; }

    let new_flags = update_access_flags(access_flags.value);
    if access_flags.value == new_flags { return access_flags.length; } // Skip bc identical

    let new_flags_uleb128 = write_uleb128(new_flags);

    if new_flags_uleb128.len() > access_flags.length as usize {
        warn!("New flags size ({0} bytes) for {1:#034b} as uleb128 is greater than the original size ({2} bytes), skipping...", new_flags_uleb128.len(), access_flags.value, access_flags.length);
        return access_flags.length;
    }

    if access_flags.length as usize > new_flags_uleb128.len() {
        // TODO: add 0'd bytes with the continuation bit
        warn!("New flags ({0:#034b})'s size ({1} bytes) is smaller than the original ({2:#034b}) ({3} bytes). Skipping for now...", new_flags, new_flags_uleb128.len(), access_flags.value, access_flags.length);
        return access_flags.length;
    }
    std::ptr::copy_nonoverlapping(new_flags_uleb128.as_ptr(), ptr, new_flags_uleb128.len());

    return access_flags.length;
}

fn u32_ptr_offset<T>(ptr: *const T, offset: u32) -> *mut T {
    unsafe { ptr.offset(offset as isize) as *mut T }
}

// convert ptr + offset pointing to data to a struct
fn ptr_to_struct_with_offset<T>(ptr: *const u8, offset: u32) -> &'static mut T {
    let new_ptr = u32_ptr_offset(ptr, offset) as *mut T;
    unsafe { &mut *new_ptr }
}

#[allow(unused)]
mod endian_constants {
    pub const LITTLE_ENDIAN: u32 = 0x12345678;
    pub const BIG_ENDIAN: u32 = 0x78563412;
}

#[allow(unused)]
mod access_flags {
    pub const ACC_PUBLIC: u32 = 0x1;
    pub const ACC_PRIVATE: u32 = 0x2;
    pub const ACC_PROTECTED: u32 = 0x4;
    pub const ACC_STATIC: u32 = 0x8;
    pub const ACC_FINAL: u32 = 0x10;
    pub const ACC_SYNCHRONIZED: u32 = 0x20;
    pub const ACC_VOLATILE: u32 = 0x40;
    pub const ACC_BRIDGE: u32 = 0x40;
    pub const ACC_TRANSIENT: u32 = 0x80;
    pub const ACC_VARARGS: u32 = 0x80;
    pub const ACC_NATIVE: u32 = 0x100;
    pub const ACC_INTERFACE: u32 = 0x200;
    pub const ACC_ABSTRACT: u32 = 0x400;
    pub const ACC_STRICT: u32 = 0x800;
    pub const ACC_SYNTHETIC: u32 = 0x1000;
    pub const ACC_ANNOTATION: u32 = 0x2000;
    pub const ACC_ENUM: u32 = 0x4000;
    pub const ACC_CONSTRUCTOR: u32 = 0x10000;
    pub const ACC_DECLARED_SYNCHRONIZED: u32 = 0x20000;
}
