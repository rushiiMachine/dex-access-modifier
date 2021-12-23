use std::fs;
use std::time::SystemTime;

use adler32::RollingAdler32;
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use log::{debug, info, warn};

#[no_mangle]
pub extern "system" fn Java_com_github_diamondminer88_dexaccessmodifier_DexAccessModifier_init(
    env: JNIEnv,
    _class: JClass,
    log_level: JString,
) {
    android_logd_logger::builder()
        .parse_filters(env.get_string(log_level).unwrap().to_str().unwrap())
        .tag("DexAccessModifier")
        .prepend_module(true)
        .init();
}

#[no_mangle]
#[allow(unaligned_references)]
pub unsafe extern "system" fn Java_com_github_diamondminer88_dexaccessmodifier_DexAccessModifier_run(env: JNIEnv, _class: JClass, input_path_: JString, output_path_: JString) {
    let input_path: String = env.get_string(input_path_).unwrap().into();
    let output_path: String = env.get_string(output_path_).unwrap().into();

    let bytes = match fs::read(input_path.clone()) {
        Ok(data) => data,
        Err(err) => {
            env.throw(format!("Failed to read file: {0}", err.to_string())).unwrap();
            return;
        }
    };

    let now = SystemTime::now();

    let header = ptr_to_struct_with_offset::<DexFileHeader>(bytes.as_ptr(), 0);

    if header.endian_tag != endian_constants::LITTLE_ENDIAN {
        env.throw("cannot handle big endian dex files").unwrap();
        return;
    }

    if header.class_defs_offset == 0 { return; } // no class defs

    let class_defs_ptr = u32_ptr_offset(bytes.as_ptr(), header.class_defs_offset);
    for class_def_idx in 0..(header.class_defs_size) {
        let item = ptr_to_struct_with_offset::<ClassDefItem>(class_defs_ptr, 0x20 * class_def_idx);

        item.access_flags = update_access_flags(item.access_flags);

        debug!("Parsing class at offset: {:#04x}", item.class_data_offset);
        if item.class_data_offset == 0 { continue; } // no data for this class

        let class_data_ptr = u32_ptr_offset(bytes.as_ptr(), item.class_data_offset);
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

        debug!("Changing field flags...");
        for _ in 0..(static_fields_size.value + instance_fields_size.value) {
            let field_idx_diff = read_uleb128(class_data_ptr, offset).unwrap();
            offset += field_idx_diff.length as u32;

            let access_flags_length = update_access_flags_uleb128(u32_ptr_offset(class_data_ptr, offset));
            offset += access_flags_length as u32;
        }

        debug!("Changing method flags...");
        for _ in 0..(direct_methods_size.value + virtual_methods_size.value) {
            let method_idx_diff = read_uleb128(class_data_ptr, offset).unwrap();
            offset += method_idx_diff.length as u32;

            let access_flags_length = update_access_flags_uleb128(u32_ptr_offset(class_data_ptr, offset));
            offset += access_flags_length as u32;

            let code_off = read_uleb128(class_data_ptr, offset).unwrap();
            offset += code_off.length as u32;
        }
    }

    let mut hasher = sha1::Sha1::new();
    hasher.update(&bytes[32..]);
    header.signature = hasher.digest().bytes();

    header.checksum = RollingAdler32::from_buffer(&bytes[12..]).hash();

    info!("Modified file {0} in {1}ms", input_path, now.elapsed().unwrap().as_millis());

    match fs::write(output_path, &bytes) {
        Err(err) => {
            env.throw(format!("Failed to write to file: {0}", err.to_string())).unwrap();
        }
        _ => {}
    }
}

fn update_access_flags(access_flags: u32) -> u32 {
    return (access_flags & !(access_flags::ACC_PRIVATE | access_flags::ACC_PROTECTED)) | access_flags::ACC_PUBLIC;
}

// returns access_flags length to be used as a further offset
unsafe fn update_access_flags_uleb128(ptr: *mut u8) -> u8 {
    let access_flags = read_uleb128(ptr, 0).unwrap();
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

fn write_uleb128(mut val: u32) -> Vec<u8> {
    const CONTINUATION_BIT: u8 = 0x80;
    let mut buf = Vec::new();
    loop {
        let mut byte = (val as u8 & std::u8::MAX) & !CONTINUATION_BIT;
        val >>= 7;
        if val != 0 {
            byte |= CONTINUATION_BIT;
        }

        buf.push(byte);

        if val == 0 {
            return buf;
        }
    }
}

#[derive(Debug)]
struct ULeb128Read {
    value: u32,
    length: u8,
}

unsafe fn read_uleb128(mut ptr: *const u8, offset: u32) -> Option<ULeb128Read> {
    const CONTINUATION_BIT: u8 = 0x80;
    ptr = ptr.offset(offset as isize);

    let mut length = 0u8;
    let mut result = 0;
    let mut shift = 0;

    loop {
        let byte = *ptr.offset(length as isize);
        length += 1;

        if shift == 63 && byte != 0x00 && byte != 0x01 {
            return None;
        }

        let low_bits = (byte & !CONTINUATION_BIT) as u32;
        result |= low_bits << shift;

        if byte & CONTINUATION_BIT == 0 {
            return Some(ULeb128Read { value: result, length });
        }

        shift += 7;
    }
}

fn u32_ptr_offset(ptr: *const u8, offset: u32) -> *mut u8 {
    unsafe { ptr.offset(offset as isize) as *mut u8 }
}

// convert ptr + offset pointing to data to a struct
fn ptr_to_struct_with_offset<T>(ptr: *const u8, offset: u32) -> &'static mut T {
    let new_ptr = u32_ptr_offset(ptr, offset) as *mut T;
    unsafe { &mut *new_ptr }
}

#[repr(C, packed)]
struct DexFileHeader {
    magic: u64,
    checksum: u32,
    signature: [u8; 20],
    file_size: u32,
    header_size: u32,
    endian_tag: u32,
    link_size: u32,
    link_offset: u32,
    map_offset: u32,
    string_ids_size: u32,
    string_ids_offset: u32,
    type_ids_size: u32,
    type_ids_offset: u32,
    proto_ids_size: u32,
    proto_ids_offset: u32,
    field_ids_size: u32,
    field_ids_offset: u32,
    method_ids_size: u32,
    method_ids_offset: u32,
    class_defs_size: u32,
    class_defs_offset: u32,
    data_size: u32,
    data_offset: u32,
}

#[repr(C, packed)]
struct ClassDefItem {
    class_idx: u32,
    access_flags: u32,
    superclass_idx: u32,
    interfaces_offset: u32,
    source_file_idx: u32,
    annotations_offset: u32,
    class_data_offset: u32,
    static_values_offset: u32,
}

#[allow(unused)]
mod endian_constants {
    pub const LITTLE_ENDIAN: u32 = 0x12345678;
    pub const BIG_ENDIAN: u32 = 0x78563412;
}

// #[allow(unused)]
// mod type_codes {
//     pub const TYPE_HEADER_ITEM: u32 = 0x0000;
//     pub const TYPE_STRING_ID_ITEM: u32 = 0x0001;
//     pub const TYPE_TYPE_ID_ITEM: u32 = 0x0002;
//     pub const TYPE_PROTO_ID_ITEM: u32 = 0x0003;
//     pub const TYPE_FIELD_ID_ITEM: u32 = 0x0004;
//     pub const TYPE_METHOD_ID_ITEM: u32 = 0x0005;
//     pub const TYPE_CLASS_DEF_ITEM: u32 = 0x0006;
//     pub const TYPE_CALL_SITE_ID_ITEM: u32 = 0x0007;
//     pub const TYPE_METHOD_HANDLE_ITEM: u32 = 0x0008;
//
//     pub const TYPE_MAP_LIST: u32 = 0x1000;
//     pub const TYPE_TYPE_LIST: u32 = 0x1001;
//     pub const TYPE_ANNOTATION_SET_REF_LIST: u32 = 0x1002;
//     pub const TYPE_ANNOTATION_SET_ITEM: u32 = 0x1003;
//
//     pub const TYPE_CLASS_DATA_ITEM: u32 = 0x2000;
//     pub const TYPE_CODE_ITEM: u32 = 0x2001;
//     pub const TYPE_STRING_DATA_ITEM: u32 = 0x2002;
//     pub const TYPE_DEBUG_INFO_ITEM: u32 = 0x2003;
//     pub const TYPE_ANNOTATION_ITEM: u32 = 0x2004;
//     pub const TYPE_ENCODED_ARRAY_ITEM: u32 = 0x2005;
//     pub const TYPE_ANNOTATIONS_DIRECTORY_ITEM: u32 = 0x2006;
//
//     pub const TYPE_HIDDENAPI_CLASS_DATA_ITEM: u32 = 0xF000;
// }

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
