[1brc](https://github.com/gunnarmorling/1brc) challenge done with Rust.

## How to run

### Generate the data 
**Warning:** The following commands will generate a "measurements_data.txt" file in the cwd and deleting it if it already exists.

First generate the data with the following command.
```
cargo run --release --bin gendata -- 12
```
This comand will generate a file with 1 billion entries using 12 cpu cores. \
You can change the number of entries by specifying like shown below.
```
cargo run --release --bin gendata -- 1 10000
```
This command will generate a file with 10000 entries using 1 cpu core.

This program currently does not generate quality measurements, you can check [the challenge base repository](https://github.com/gunnarmorling/1brc) to find a better generation method.
**Note**: A file with 1 billion entries is around 14GB. 
### Run the challenge
First build the release target running the following command.
```
cargo build --release 
```
Then locate your measurments data file and run the following command. 
```
time ./target/release/onbrc-challenge /path/to/measurments_data 12
```
This will run and time the challenge on the provided file using 12 cpu cores.

Make sure the measurments file is well formatted as specified [here](https://github.com/gunnarmorling/1brc) because no validity checks are made in the program.