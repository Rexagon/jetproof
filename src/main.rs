use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use crossbeam_channel as mpsc;
use everscale_types::dict::DictKey;
use everscale_types::error::Error;
use everscale_types::merkle::MerkleProof;
use everscale_types::models::*;
use everscale_types::num::Tokens;
use everscale_types::prelude::*;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use rand::Rng;
use rayon::iter::ParallelIterator;
use rayon::slice::{ParallelSlice, ParallelSliceMut};

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn main() -> Result<()> {
    let App { cmd } = argh::from_env();
    match cmd {
        Cmd::Build(cmd) => cmd.run(),
        Cmd::Verify(cmd) => cmd.run(),
        Cmd::Test(cmd) => cmd.run(),
        Cmd::Generate(cmd) => cmd.run(),
    }
}

/// A tool for creating huge jetton offchain merkle proofs.
#[derive(argh::FromArgs)]
struct App {
    /// subcommand.
    #[argh(subcommand)]
    cmd: Cmd,
}

#[derive(argh::FromArgs)]
#[argh(subcommand)]
enum Cmd {
    Build(BuildProofs),
    Verify(VerifyProofs),
    Test(TestProof),
    Generate(GenerateParticipants),
}

/// Build merkle proofs from a csv file.
#[derive(argh::FromArgs)]
#[argh(subcommand, name = "build")]
struct BuildProofs {
    /// path to the csv file (address, amount).
    #[argh(positional)]
    input: PathBuf,

    /// path to the output csv file (address, proof).
    #[argh(positional)]
    output: Option<PathBuf>,

    /// a unix timestamp when the airdrop starts. (default: now)
    #[argh(option)]
    start_from: Option<u64>,

    /// a unix timestamp when the airdrop ends. (default: never)
    #[argh(option)]
    expire_at: Option<u64>,

    /// overwrite the output file if it exists.
    #[argh(switch, short = 'f')]
    force: bool,

    /// hide the progress bar.
    #[argh(switch, short = 'q')]
    quiet: bool,
}

impl BuildProofs {
    fn run(self) -> Result<()> {
        if matches!(&self.output, Some(output) if output.exists() && !self.force) {
            anyhow::bail!("Output file already exists. Use `--force` to overwrite it.");
        }

        let start_from = self.start_from.unwrap_or_else(now_sec);
        let expire_at = self.expire_at.unwrap_or(EXPIRE_NEVER);

        let pg = ProgressBar::new_spinner();
        if self.quiet {
            pg.set_draw_target(ProgressDrawTarget::hidden());
        }

        pg.enable_steady_tick(Duration::from_millis(100));

        let entries = read_csv_amounts(&pg, &self.input)?;

        let Some(dict_root) = build_dict(&pg, &entries, start_from, expire_at)? else {
            anyhow::bail!("no entries found");
        };

        if let Some(output) = &self.output {
            build_proofs(&pg, &entries, &dict_root, output)?;
        }

        pg.finish_and_clear();
        pg.println("Done!");

        let output = serde_json::json!({
            "dict_root": dict_root.repr_hash().to_string(),
            "start_from": start_from,
            "expire_at": expire_at,
        });
        let output = if std::io::stdout().is_terminal() {
            serde_json::to_string_pretty(&output)?
        } else {
            serde_json::to_string(&output)?
        };
        println!("{output}");

        std::mem::forget(dict_root);
        Ok(())
    }
}

type AirdropEntry = (StdAddr, Tokens);

fn read_csv_amounts(pg: &ProgressBar, path: &PathBuf) -> Result<Vec<AirdropEntry>> {
    pg.println("Reading the csv input...");
    pg.reset();
    pg.set_style(ProgressStyle::with_template("{spinner} Lines read: {human_len}").unwrap());

    let file = std::fs::OpenOptions::new().read(true).open(path)?;
    let reader = std::io::BufReader::new(file);

    let mut result = Vec::new();
    for (line, data) in reader.lines().enumerate() {
        let line = line + 1;
        let data = data?;

        let Some((address, amount)) = data.split_once(',') else {
            anyhow::bail!("invalid csv line: {line}");
        };

        let address = address
            .trim()
            .parse::<StdAddr>()
            .with_context(|| format!("line {line}"))?;

        let amount = amount
            .trim()
            .parse::<Tokens>()
            .with_context(|| format!("line {line}"))?;

        result.push((address, amount));

        pg.inc(1);
    }

    pg.println("Sorting entries...");
    result.par_sort_unstable_by_key(|(addr, _)| addr.clone());

    Ok(result)
}

fn build_dict(
    pg: &ProgressBar,
    entries: &[AirdropEntry],
    start_from: u64,
    expire_at: u64,
) -> Result<Option<Cell>, Error> {
    struct AirdropData {
        amount: Tokens,
        start_from: u64,
        expire_at: u64,
    }

    impl Store for AirdropData {
        fn store_into(&self, b: &mut CellBuilder, cx: &mut dyn CellContext) -> Result<(), Error> {
            self.amount.store_into(b, cx)?;
            b.store_uint(self.start_from, 48)?;
            b.store_uint(self.expire_at, 48)
        }
    }

    const TICK_STEP: usize = 1000;

    pg.println("Building the dictionary...");
    pg.reset();
    pg.set_style(pg_style());
    pg.set_position(0);
    pg.set_length(entries.len() as _);

    let root = everscale_types::dict::build_dict_from_sorted_iter(
        entries.iter().enumerate().map(|(i, (addr, amount))| {
            if i % TICK_STEP == 0 {
                pg.inc(TICK_STEP as _);
            }

            (
                addr.clone(),
                AirdropData {
                    amount: *amount,
                    start_from,
                    expire_at,
                },
            )
        }),
        <StdAddr as DictKey>::BITS,
        &mut Cell::empty_context(),
    )?;

    Ok(root)
}

fn build_proofs(
    pg: &ProgressBar,
    entries: &[AirdropEntry],
    dict_root: &Cell,
    output: &Path,
) -> Result<()> {
    use everscale_types::boc::ser::BocHeader;

    pg.println("Building proofs...");
    pg.reset();
    pg.set_style(pg_style());
    pg.set_position(0);
    pg.set_length(entries.len() as _);

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(output)?;

    let num_threads = std::thread::available_parallelism()?.get();
    let (filled_buffers_tx, filled_buffers_rx) = mpsc::bounded::<Vec<u8>>(num_threads);
    let (empty_buffers_tx, empty_buffers_rx) = mpsc::bounded::<Vec<u8>>(num_threads);

    for _ in 0..num_threads {
        empty_buffers_tx.send(Vec::new()).unwrap();
    }

    let writer_thread = std::thread::spawn(move || {
        while let Ok(mut buffer) = filled_buffers_rx.recv() {
            file.write_all(&buffer).unwrap();
            buffer.clear();
            empty_buffers_tx.send(buffer).unwrap();
        }

        file
    });

    const CHUNK_SIZE: usize = 1 << 13;
    entries.par_chunks(CHUNK_SIZE).for_each(|chunk| {
        let mut buffer = empty_buffers_rx.recv().unwrap();

        let mut first = true;

        let mut boc_buffer = Vec::new();
        for (addr, _) in chunk {
            let newline = if std::mem::take(&mut first) { "" } else { "\n" };
            write!(buffer, "{newline}{addr},",).unwrap();

            let usage_tree = UsageTree::new(UsageTreeMode::OnDataAccess);

            {
                let dict_root = usage_tree.track(dict_root);
                Dict::<StdAddr, ()>::from_raw(Some(dict_root))
                    .get(addr)
                    .ok();
            }

            let proof = MerkleProof::create(dict_root.as_ref(), usage_tree)
                .build()
                .unwrap();
            let proof = CellBuilder::build_from(proof).unwrap();
            BocHeader::<ahash::RandomState>::with_root(proof.as_ref())
                .encode_rayon(&mut boc_buffer);

            base64_simd::STANDARD.encode_append(&boc_buffer, &mut buffer);

            boc_buffer.clear();

            pg.inc(1);
        }
        if !first {
            buffer.push(b'\n');
        }

        filled_buffers_tx.send(buffer).unwrap();
    });

    drop(filled_buffers_tx);

    let mut file = writer_thread.join().unwrap();

    pg.println("Flushing the output file...");

    file.flush()?;
    drop(file);

    Ok(())
}

/// Verify merkle proofs from a csv file.
#[derive(argh::FromArgs)]
#[argh(subcommand, name = "verify")]
struct VerifyProofs {
    /// path to the csv file (address, amount).
    #[argh(positional)]
    input: PathBuf,

    /// root hash of the dictionary.
    #[argh(option, short = 'r')]
    root_hash: HashBytes,

    /// hide the progress bar.
    #[argh(switch, short = 'q')]
    quiet: bool,
}

impl VerifyProofs {
    fn run(self) -> Result<()> {
        let pg = ProgressBar::new_spinner();
        if self.quiet {
            pg.set_draw_target(ProgressDrawTarget::hidden());
        }

        pg.println("Reading the csv input...");
        pg.set_style(
            ProgressStyle::with_template("{spinner} Proofs checked: {human_len}").unwrap(),
        );
        pg.enable_steady_tick(Duration::from_millis(100));

        let file = std::fs::OpenOptions::new().read(true).open(self.input)?;
        let reader = std::io::BufReader::new(file);

        let mut proof_boc_buffer = Vec::new();
        for (line, data) in reader.lines().enumerate() {
            let line = line + 1;
            let data = data?;

            let Some((address, proof)) = data.split_once(',') else {
                anyhow::bail!("invalid csv line: {line}");
            };

            let address = address
                .trim()
                .parse::<StdAddr>()
                .with_context(|| format!("line {line}"))?;

            base64_simd::STANDARD.decode_append(proof, &mut proof_boc_buffer)?;

            let proof = Boc::decode(&proof_boc_buffer)?;
            proof_boc_buffer.clear();

            let proof = proof.parse::<MerkleProof>()?;
            anyhow::ensure!(
                proof.hash == self.root_hash,
                "invalid root hash for {address}"
            );

            let entry = Dict::<StdAddr, ()>::from_raw(Some(proof.cell)).get(&address)?;
            anyhow::ensure!(entry.is_some(), "{address} is not a participant");

            pg.inc(1);
        }

        pg.finish_and_clear();

        pg.println("Done!");
        Ok(())
    }
}

/// Test a single proof.
#[derive(argh::FromArgs)]
#[argh(subcommand, name = "test")]
struct TestProof {
    /// account address.
    #[argh(option, short = 'a')]
    address: StdAddr,

    /// base64 encoded proof.
    #[argh(option, short = 'p')]
    proof: String,

    /// root hash of the dictionary.
    #[argh(option, short = 'r')]
    root_hash: HashBytes,
}

impl TestProof {
    fn run(self) -> Result<()> {
        let proof = Boc::decode(base64_simd::STANDARD.decode_to_vec(&self.proof)?)?;
        let proof = proof.parse::<MerkleProof>()?;

        let is_proof_valid;
        let mut is_participant = false;
        'check: {
            is_proof_valid = proof.hash == self.root_hash;
            if !is_proof_valid {
                break 'check;
            }

            let entry = Dict::<StdAddr, ()>::from_raw(Some(proof.cell)).get(&self.address)?;
            is_participant = entry.is_some();
        }

        let output = serde_json::json!({
            "is_proof_valid": is_proof_valid,
            "is_participant": is_participant,
        });
        let output = if std::io::stdout().is_terminal() {
            serde_json::to_string_pretty(&output)?
        } else {
            serde_json::to_string(&output)?
        };

        println!("{output}");
        Ok(())
    }
}

/// Generate a csv file with random participants.
#[derive(argh::FromArgs)]
#[argh(subcommand, name = "generate")]
struct GenerateParticipants {
    /// path to the output csv file.
    #[argh(positional)]
    output: PathBuf,

    /// number of participants.
    #[argh(option, short = 'n')]
    number: u64,

    /// overwrite the output file if it exists.
    #[argh(switch, short = 'f')]
    force: bool,

    /// hide the progress bar.
    #[argh(switch, short = 'q')]
    quiet: bool,
}

impl GenerateParticipants {
    fn run(self) -> Result<()> {
        if self.output.exists() && !self.force {
            anyhow::bail!("Output file already exists. Use `--force` to overwrite it.");
        }

        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(self.output)?;
        let mut writer = std::io::BufWriter::new(file);

        let pg = ProgressBar::new(self.number);
        if self.quiet {
            pg.set_draw_target(ProgressDrawTarget::hidden());
        }

        pg.println("Generating random entries...");
        pg.enable_steady_tick(Duration::from_millis(100));
        pg.set_style(pg_style());

        let rng = &mut rand::thread_rng();
        for _ in 0..self.number {
            let address = StdAddr::new(0, HashBytes(rng.gen()));
            let amount = rng.gen_range::<u64, _>(1..100_000) as u128 * 1_000_000_000;

            writer.write_fmt(format_args!("{address},{amount}\n"))?;
            pg.inc(1);
        }

        pg.finish_and_clear();
        pg.println("Flushing the output file...");

        writer.flush()?;
        drop(writer);

        pg.println("Done!");
        Ok(())
    }
}

fn now_sec() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn pg_style() -> ProgressStyle {
    ProgressStyle::with_template("[ETA {eta_precise}] {bar:40} {pos:>7}/{len:7} {msg}").unwrap()
}

const EXPIRE_NEVER: u64 = (1 << 48) - 1;
