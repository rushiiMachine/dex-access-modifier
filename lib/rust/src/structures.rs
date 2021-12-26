pub mod structures {
    #[repr(C, packed)]
    pub struct DexFileHeader {
        pub magic: u64,
        pub checksum: u32,
        pub signature: [u8; 20],
        pub file_size: u32,
        pub header_size: u32,
        pub endian_tag: u32,
        pub link_size: u32,
        pub link_offset: u32,
        pub map_offset: u32,
        pub string_ids_size: u32,
        pub string_ids_offset: u32,
        pub type_ids_size: u32,
        pub type_ids_offset: u32,
        pub proto_ids_size: u32,
        pub proto_ids_offset: u32,
        pub field_ids_size: u32,
        pub field_ids_offset: u32,
        pub method_ids_size: u32,
        pub method_ids_offset: u32,
        pub class_defs_size: u32,
        pub class_defs_offset: u32,
        pub data_size: u32,
        pub data_offset: u32,
    }

    #[repr(C, packed)]
    pub struct ClassDefItem {
        pub class_idx: u32,
        pub access_flags: u32,
        pub superclass_idx: u32,
        pub interfaces_offset: u32,
        pub source_file_idx: u32,
        pub annotations_offset: u32,
        pub class_data_offset: u32,
        pub static_values_offset: u32,
    }
}