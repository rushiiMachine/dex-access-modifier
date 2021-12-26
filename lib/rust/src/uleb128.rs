pub mod uleb128 {
    const CONTINUATION_BIT: u8 = 0x80;

    pub fn write_uleb128(mut val: u32) -> Vec<u8> {
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

    pub struct ULeb128Read {
        pub value: u32,
        pub length: u8,
    }

    pub unsafe fn read_uleb128(mut ptr: *const u8, offset: u32) -> Option<ULeb128Read> {
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
}
