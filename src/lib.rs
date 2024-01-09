#![feature(test)]
extern crate test;

pub mod challenge {
    use std::{collections::HashMap, fs::read_to_string, path::Path};

    pub fn run(file_path: &Path) -> Result<String, String> {
        let data = read_to_string(file_path).map_err(|err| err.to_string())?;
        let mut lookup: HashMap<&str, (i32, f32, f32, f32)> = HashMap::new();
        for line in data.lines() {
            let (name, temp) = parse_line(line);
            let entry = lookup.entry(name).or_insert((0, f32::MAX, f32::MIN, 0.));
            entry.0 += 1;
            entry.1 = entry.1.min(temp);
            entry.2 = entry.2.max(temp);
            entry.3 += temp;
        }
        let mut records = lookup
            .into_iter()
            .collect::<Vec<(&str, (i32, f32, f32, f32))>>();
        records.sort_unstable_by_key(|(name, ..)| *name);
        let mut out = String::new();
        out.push('{');
        out.push_str(
            records
                .into_iter()
                .map(|(name, (cnt, min, max, total))| {
                    format!(
                        "{name}={min:.1}/{mean:.1}/{max:.1}",
                        mean = total / cnt as f32
                    )
                })
                .collect::<Vec<String>>()
                .join(", ")
                .as_str(),
        );
        out.push('}');
        Ok(out)
    }

    fn parse_line(line: &str) -> (&str, f32) {
        let split = line.find(';').expect("No ';' found in line");
        let (name, temp) = line.split_at(split);
        (
            name,
            temp[1..]
                .parse::<f32>()
                .expect("Unable to parse text into float"),
        )
    }
}

#[cfg(test)]
mod tests {

    use test::Bencher;

    #[bench]
    fn bench_unique_small(b: &mut Bencher) {
        b.iter(|| {
            super::challenge::run("sample/measurements-20.txt".to_string().as_ref())
                .expect("Unable to read input file");
        });
    }
    #[test]
    fn test_unique_small() {
        use std::fs::read_to_string;
        let expected_out =
            read_to_string("sample/measurements-20.out").expect("Unable to read output file");
        let out = super::challenge::run("sample/measurements-20.txt".to_string().as_ref())
            .expect("Unable to read input file");
        assert!(
            expected_out == out,
            "Expected:\n{expected_out}\nGot:\n{out}"
        );
    }
    #[bench]
    fn bench_unique_big(b: &mut Bencher) {
        b.iter(|| {
            super::challenge::run(
                "sample/measurements-10000-unique-keys.txt"
                    .to_string()
                    .as_ref(),
            )
            .expect("Unable to read input file");
        });
    }
    #[test]
    fn test_unique_big() {
        use std::fs::read_to_string;
        let expected_out = read_to_string("sample/measurements-10000-unique-keys.out")
            .expect("Unable to read output file");
        let out = super::challenge::run(
            "sample/measurements-10000-unique-keys.txt"
                .to_string()
                .as_ref(),
        )
        .expect("Unable to read input file");
        println!("{}, {}", &expected_out.as_str()[..50], &out.as_str()[..50]);
        assert!(expected_out == out, "Diff at index:{}", {
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
        });
    }
}
