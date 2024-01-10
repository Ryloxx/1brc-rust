// Repo:
//  https://github.com/gunnarmorling/1brc.git
// Rules:
//  Any of these Java distributions may be used:
//  Any builds provided by SDKMan
//  Early access builds available on openjdk.net may be used (including EA
// builds  for OpenJDK projects like Valhalla) Builds on builds.shipilev.net If
// you want  to use a build not available via these channels, reach out to
// discuss whether  it can be considered. No external library dependencies may
// be used  Implementations must be provided as a single source file
//  The computation must happen at application runtime, i.e. you cannot process
//  the measurements file at build time (for instance, when using GraalVM) and
//  just bake the result into the binary Input value ranges are as follows:
//  Station name: non null UTF-8 string of min length 1 character and max length
//  100 bytes (i.e. this could be 100 one-byte characters, or 50 two-byte
//  characters, etc.) Temperature value: non null double between -99.9
//  (inclusive) and 99.9 (inclusive), always with one fractional digit There is
// a  maximum of 10,000 unique station names Implementations must not rely on
//  specifics of a given data set, e.g. any valid station name as per the
//  constraints above and any data distribution (number of measurements per
//  station) must be supported

use std::{env::args, num::NonZeroU8, path::Path};

use onebrc_challenge::challenge;

fn main() -> Result<(), String> {
    let output = challenge::run(
        Path::new(
            args()
                .nth(1)
                .ok_or_else(|| "Missing file path argument".to_string())?
                .as_str(),
        ),
        NonZeroU8::new(
            args()
                .nth(2)
                .unwrap_or("1".to_string())
                .parse::<u8>()
                .map_err(|err| err.to_string())?,
        )
        .ok_or_else(|| "Wrong num cpus number".to_string())?,
    )?;
    println!("{output}");
    Ok(())
}
