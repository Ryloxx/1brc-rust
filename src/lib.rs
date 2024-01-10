#![feature(test)]
#![feature(hash_raw_entry)]
extern crate libc;
extern crate test;
pub mod challenge {
    use core::slice;
    use std::{
        collections::HashMap,
        fs::OpenOptions,
        hash::{BuildHasherDefault, Hasher},
        num::NonZeroU8,
        ops::BitXor,
        os::fd::AsRawFd,
        path::Path,
        ptr,
        thread::JoinHandle,
    };
    struct CHash {
        hash: u64,
    }

    impl CHash {
        #[inline]
        fn roll(&mut self, part: u64) {
            self.hash = self
                .hash
                .rotate_left(5)
                .bitxor(part)
                .wrapping_mul(0x517cc1b727220a95);
        }
    }
    #[allow(clippy::derivable_impls)]
    impl Default for CHash {
        fn default() -> Self {
            Self { hash: 0 }
        }
    }
    impl Hasher for CHash {
        fn finish(&self) -> u64 {
            self.hash
        }

        fn write(&mut self, mut bytes: &[u8]) {
            while bytes.len() >= 8 {
                self.roll(u64::from_ne_bytes(bytes[..8].try_into().unwrap()));
                bytes = &bytes[8..];
            }
            if bytes.len() >= 4 {
                self.roll(u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as u64);
                bytes = &bytes[4..];
            }
            if bytes.len() >= 2 {
                self.roll(u16::from_ne_bytes(bytes[..2].try_into().unwrap()) as u64);
                bytes = &bytes[2..];
            }
            if !bytes.is_empty() {
                self.roll(bytes[0] as u64);
            }
        }
    }

    struct MemMapped {
        pub length: u64,
        mem_base: *mut libc::c_void,
    }
    impl MemMapped {
        pub fn base(&self) -> *const u8 {
            self.mem_base as *const u8
        }
        pub fn new(file_path: &Path) -> Result<Self, String> {
            let file = OpenOptions::new()
                .read(true)
                .open(file_path)
                .map_err(|err| err.to_string())?;
            let length = file.metadata().unwrap().len();
            let mapped_mem_base = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    length as usize,
                    libc::PROT_READ,
                    libc::MAP_PRIVATE,
                    file.as_raw_fd(),
                    0,
                )
            };
            if mapped_mem_base == libc::MAP_FAILED {
                return Err(format!(
                    "Memory mapping failed: {}",
                    std::io::Error::last_os_error()
                ));
            };
            Ok(Self {
                mem_base: mapped_mem_base,
                length,
            })
        }
    }
    impl Drop for MemMapped {
        fn drop(&mut self) {
            if unsafe { libc::munmap(self.mem_base, self.length as usize) } == -1 {
                eprintln!(
                    "Memory unmapping failed: {}",
                    std::io::Error::last_os_error()
                )
            };
        }
    }

    type Key = String;
    type Value = (i32, i32, i32, i64);
    // Chose the hasher here
    type Builder = BuildHasherDefault<CHash>;
    type Lookup = HashMap<Key, Value, Builder>;

    pub fn run(file_path: &Path, num_cpus: NonZeroU8) -> Result<String, String> {
        let data = MemMapped::new(file_path)?;
        let num_cpus = num_cpus.get();
        let chunk_size = data.length / num_cpus as u64;
        let segments_count = data.length / chunk_size;
        let lookup = (0..segments_count)
            .map(|segment| {
                let from = segment * chunk_size;
                let base = data.base() as usize;
                std::thread::spawn(move || {
                    let base = base as *const u8;
                    let mut offset = start_of_line_offset(base, from, data.length);
                    let mut lookup: Lookup = HashMap::default();
                    let mut measurement = (String::with_capacity(100), 0);
                    while (offset - from) < chunk_size && offset < data.length {
                        // No data validity check made for speed purpose, so this is not safe indeed
                        unsafe { process_entry(&mut measurement, base, &mut offset) };
                        handle_entry(&mut lookup, &measurement.0, measurement.1);
                        // Go to next line
                        offset += 1;
                    }
                    lookup
                })
            })
            .collect::<Vec<JoinHandle<Lookup>>>()
            .into_iter()
            .flat_map(JoinHandle::join)
            .reduce(merge_lookups)
            .unwrap_or_default();
        Ok(generate_output(lookup))
    }

    fn merge_lookups(mut a: Lookup, b: Lookup) -> Lookup {
        for (key, value) in b.into_iter() {
            if let Some(entry) = a.get_mut(&key) {
                entry.0 += value.0;
                entry.1 = entry.1.min(value.1);
                entry.2 = entry.2.max(value.2);
                entry.3 += value.3;
            } else {
                a.insert(key, value);
            }
        }
        a
    }

    /// Expect data to contain valid utf-8 \
    /// Expect offset to be in data bounds and pointing at the start of a
    /// codepoint. \
    /// Expect entry to be formatted as
    /// <string: stationname>;<double:measurement> \
    /// The resulting offset will point after the entry
    unsafe fn process_entry(out: &mut (String, i32), data: *const u8, offset: &mut u64) {
        out.0.clear();
        out.1 = 0;
        {
            let start = *offset;
            loop {
                if *data.add(*offset as usize) == b';' {
                    break;
                }
                *offset += 1;
            }
            let len = (*offset - start) as usize;
            let v = out.0.as_mut_vec();
            v.resize(len, 0);
            v.as_mut_slice()
                .copy_from_slice(slice::from_raw_parts(data.add(start as usize), len))
        }
        let sign = *data.add(*offset as usize + 1) == b'-';
        if sign {
            *offset += 1;
        }
        for _ in 0..3 {
            *offset += 1;
            match *data.add(*offset as usize) {
                b'.' => {
                    *offset += 1;
                    out.1 *= 10;
                    out.1 += (*data.add(*offset as usize) - b'0') as i32;
                    out.1 = if sign { -out.1 } else { out.1 };
                    *offset += 1;
                    break;
                }
                c => {
                    out.1 *= 10;
                    out.1 += (c - b'0') as i32;
                }
            }
        }
    }

    fn generate_output(lookup: Lookup) -> String {
        let mut records = lookup.into_iter().collect::<Vec<(Key, Value)>>();
        records.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let mut out = String::new();
        out.push('{');
        out.push_str(
            records
                .into_iter()
                .map(|(name, (cnt, min, max, total))| {
                    format!(
                        "{name}={:.1}/{:.1}/{:.1}",
                        min as f32 / 10.,
                        (total / cnt as i64) as f32 / 10.,
                        max as f32 / 10.,
                    )
                })
                .collect::<Vec<String>>()
                .join(", ")
                .as_str(),
        );
        out.push('}');
        out
    }

    fn start_of_line_offset(m_mem: *const u8, from: u64, len: u64) -> u64 {
        if from == 0 {
            return 0;
        }
        for offset in from..len {
            let c = *(unsafe { m_mem.add(offset as usize - 1).as_ref().unwrap() });
            if c == b'\n' {
                return offset;
            }
        }
        len - 1
    }

    fn handle_entry(lookup: &mut Lookup, name: &Key, temp: i32) {
        let entry = lookup
            .raw_entry_mut()
            .from_key(name)
            .or_insert_with(|| (name.to_owned(), (0, i32::MAX, i32::MIN, 0)))
            .1;
        entry.0 += 1;
        entry.1 = entry.1.min(temp);
        entry.2 = entry.2.max(temp);
        entry.3 += temp as i64;
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU8;
    use test::Bencher;
    #[bench]
    fn bench_unique_small(b: &mut Bencher) {
        b.iter(|| run_file("sample/measurements-20.txt"));
    }
    #[test]
    fn test_unique_small() {
        run_test("sample/measurements-20.txt", "sample/measurements-20.out");
    }
    #[bench]
    fn bench_unique_medium(b: &mut Bencher) {
        b.iter(|| run_file("sample/measurements-10000-unique-keys.txt"));
    }
    #[test]
    fn test_unique_medium() {
        run_test(
            "sample/measurements-10000-unique-keys.txt",
            "sample/measurements-10000-unique-keys.out",
        );
    }

    fn run_test(input_path: &str, output_path: &str) {
        use std::fs::read_to_string;
        let expected_out = read_to_string(output_path).expect("Unable to read output file");
        let out = run_file(input_path);
        assert_equal(expected_out, out);
    }

    fn run_file(input_path: &str) -> String {
        super::challenge::run(input_path.to_string().as_ref(), NonZeroU8::MIN)
            .expect("Unable to read input file")
    }
    fn assert_equal(expected_out: String, out: String) {
        let diff_index = {
            let mut index = !0;
            for (i, (a, b)) in expected_out
                .as_bytes()
                .iter()
                .zip(out.as_bytes().iter())
                .enumerate()
            {
                if a != b {
                    index = i;
                    break;
                }
            }
            index
        };
        if diff_index < expected_out.len() {
            println!(
                "Expected:\n{}\nGot:\n{}",
                &expected_out.as_str()[..diff_index + 1],
                &out.as_str()[..diff_index + 1]
            );
        }
        assert!(diff_index == !0, "Diff at index:{}", diff_index);
    }
}
