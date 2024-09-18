use std::cell::RefCell;
use std::num::NonZeroU8;
use std::sync::Arc;
use std::time::Duration;
use std::u8;

use anyhow::{Context, Result};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{self, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use clap::Parser;
use everscale_types::boc::Boc;
use everscale_types::cell::{Cell, CellBuilder, CellFamily, HashBytes, Store};
use everscale_types::dict::Dict;
use everscale_types::models::{StateInit, StdAddr};
use everscale_types::num::Tokens;
use once_cell::race::OnceBox;
use serde::{Deserialize, Serialize};
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;

use self::config::Config;
use self::storage::{Storage, StorageConfig, UserProofsIterBuilder};

mod config;
mod storage;

#[derive(Parser)]
pub struct Cmd {
    #[clap(long)]
    pub tokio_workers: Option<usize>,
}

impl Cmd {
    pub fn run(self) -> Result<()> {
        init_logger();

        let mut builder = tokio::runtime::Builder::new_multi_thread();

        if let Some(tokio_workers) = self.tokio_workers {
            builder.worker_threads(tokio_workers);
        }

        builder.enable_all().build()?.block_on(run())
    }
}

async fn run() -> Result<()> {
    let config = ::config::Config::builder()
        .add_source(::config::File::with_name("config").required(false))
        .add_source(::config::Environment::with_prefix("JETPROOF"))
        .build()
        .context("failed to read config")?
        .try_deserialize::<Config>()
        .context("failed to deserialize config")?;

    let storage = Storage::new(StorageConfig {
        path: config.storage_path,
        cache_capacity: config.storage_cache,
    })?;
    let total_wallets = storage.count_addresses()?;
    tracing::info!(
        version = storage.version(),
        start_from = storage.start_from(),
        expire_at = storage.expire_at(),
        total_wallets,
        "initialized storage"
    );

    STATE_RESPONSE
        .set(Box::new(
            serde_json::to_string(&serde_json::json!({
                "total_wallets": total_wallets.to_string(),
                "address": config.master_addr.to_string(),
            }))?
            .into(),
        ))
        .unwrap();

    // Prepare middleware
    let service = ServiceBuilder::new()
        .layer(DefaultBodyLimit::max(MAX_REQUEST_SIZE))
        .layer(CorsLayer::permissive())
        .layer(TimeoutLayer::new(Duration::from_secs(1)));

    let app = Router::new()
        .route("/wallet/:address", get(get_wallet))
        .route("/wallets", get(get_wallets))
        .route("/state", get(get_state))
        .layer(service)
        .with_state(Arc::new(ApiState {
            storage,
            wallet_code: config.wallet_code,
            master_addr: config.master_addr,
        }));

    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    tracing::info!(listen_addr = %config.listen_addr, "started listening");

    axum::serve(listener, app).await.map_err(Into::into)
}

type SharedApiState = Arc<ApiState>;

struct ApiState {
    storage: Storage,
    wallet_code: Cell,
    master_addr: StdAddr,
}

fn get_wallet(
    State(state): State<SharedApiState>,
    Path(address): Path<StdAddr>,
) -> futures_util::future::Ready<Response> {
    let state = state.as_ref();
    let Some(proof) = state.storage.get_proof(&address) else {
        return futures_util::future::ready(
            (JSON_HEADERS, axum::body::Bytes::from_static(b"{}")).into_response(),
        );
    };

    let (jetton_wallet, state_init) = {
        let cell = compute_wallet_state_init(
            state.wallet_code.clone(),
            &address,
            &state.master_addr,
            state.storage.root_hash(),
        )
        .unwrap();

        let addr = StdAddr::new(0, *cell.repr_hash());
        let boc = Boc::encode(cell);
        (addr, base64_simd::STANDARD.encode_to_string(boc))
    };

    let (amount, custom_payload) = proof.read();

    let value = simd_json::to_vec(&WalletResponse {
        owner: &address,
        jetton_wallet: &jetton_wallet,
        custom_payload,
        state_init: &state_init,
        compressed_info: CompressedInfo {
            amount,
            start_from: state.storage.start_from(),
            expired_at: state.storage.expire_at(),
        },
    })
    .unwrap();

    futures_util::future::ready((JSON_HEADERS, axum::body::Bytes::from(value)).into_response())
}

fn get_wallets(
    State(state): State<SharedApiState>,
    Query(query): Query<WalletsQuery>,
) -> futures_util::future::Ready<Response> {
    let state = state.as_ref();
    let proofs = state.storage.get_proofs(&query.start_from);

    let limit = query
        .count
        .map(|c| c.get())
        .unwrap_or(u8::MAX)
        .min(WalletsResponse::MAX_LIMIT);

    let value = simd_json::to_vec(&WalletsResponse {
        state,
        list: RefCell::new(Some(proofs)),
        limit,
    })
    .unwrap();

    futures_util::future::ready((JSON_HEADERS, axum::body::Bytes::from(value)).into_response())
}

fn get_state() -> futures_util::future::Ready<Response> {
    let buf = STATE_RESPONSE.get().unwrap();

    futures_util::future::ready((JSON_HEADERS, buf.clone()).into_response())
}

static STATE_RESPONSE: OnceBox<Bytes> = OnceBox::new();

const JSON_HEADERS: [(http::HeaderName, HeaderValue); 1] = [(
    http::header::CONTENT_TYPE,
    HeaderValue::from_static("application/json"),
)];

#[derive(Deserialize)]
struct WalletsQuery {
    start_from: StdAddr,
    count: Option<NonZeroU8>,
}

struct WalletsResponse<'a> {
    state: &'a ApiState,
    list: RefCell<Option<UserProofsIterBuilder<'a>>>,
    limit: u8,
}

impl WalletsResponse<'_> {
    const MAX_LIMIT: u8 = 50;
}

impl Serialize for WalletsResponse<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::{SerializeSeq, SerializeStruct};

        struct WalletsList<'a> {
            state: &'a ApiState,
            list: RefCell<Option<UserProofsIterBuilder<'a>>>,
            next_from: RefCell<Option<StdAddr>>,
            limit: u8,
        }

        impl Serialize for WalletsList<'_> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let list = self.list.borrow_mut().take().unwrap();

                // NOTE: We cannot use `limit` as the sequence length because
                // the iterator may return less.
                let mut seq = serializer.serialize_seq(match list.is_valid() {
                    true => None,
                    false => Some(0),
                })?;

                let mut boc_buffer = Vec::new();
                let mut state_init_buffer = String::new();

                let mut iter = list.map(|addr, proof| {
                    let (amount, custom_payload) = proof.read();

                    let jetton_wallet = {
                        let cell = compute_wallet_state_init(
                            self.state.wallet_code.clone(),
                            &addr,
                            &self.state.master_addr,
                            self.state.storage.root_hash(),
                        )
                        .unwrap();

                        boc_buffer.clear();
                        everscale_types::boc::ser::BocHeader::<ahash::RandomState>::with_root(
                            cell.as_ref(),
                        )
                        .encode(&mut boc_buffer);

                        state_init_buffer.clear();
                        base64_simd::STANDARD.encode_append(&boc_buffer, &mut state_init_buffer);

                        StdAddr::new(0, *cell.repr_hash())
                    };

                    seq.serialize_element(&WalletResponse {
                        owner: &addr,
                        jetton_wallet: &jetton_wallet,
                        custom_payload,
                        state_init: &state_init_buffer,
                        compressed_info: CompressedInfo {
                            amount,
                            start_from: self.state.storage.start_from(),
                            expired_at: self.state.storage.expire_at(),
                        },
                    })
                });

                iter.by_ref()
                    .take(self.limit as usize)
                    .collect::<Result<(), _>>()?;

                *self.next_from.borrow_mut() = iter.into_next_from();

                seq.end()
            }
        }

        let mut s = serializer.serialize_struct("Wallets", 2)?;

        let list = self.list.borrow_mut().take();
        let list = WalletsList {
            state: self.state,
            list: RefCell::new(list),
            next_from: RefCell::new(None),
            limit: self.limit,
        };
        s.serialize_field("wallets", &list)?;

        match &*list.next_from.borrow() {
            Some(next_from) => s.serialize_field("next_from", next_from)?,
            // FIXME: Skip field if `None`?
            None => s.serialize_field("next_from", &"")?,
        }

        s.end()
    }
}

#[derive(Serialize)]
struct WalletResponse<'a> {
    owner: &'a StdAddr,
    jetton_wallet: &'a StdAddr,
    custom_payload: &'a str,
    state_init: &'a str,
    compressed_info: CompressedInfo,
}

#[derive(Serialize)]
struct CompressedInfo {
    #[serde(serialize_with = "serde_string")]
    amount: u128,
    #[serde(serialize_with = "serde_string")]
    start_from: u64,
    #[serde(serialize_with = "serde_string")]
    expired_at: u64,
}

fn compute_wallet_state_init(
    code: Cell,
    owner: &StdAddr,
    master_addr: &StdAddr,
    merkle_root: &HashBytes,
) -> Result<Cell, everscale_types::error::Error> {
    let cx = &mut Cell::empty_context();
    let data = {
        let mut builder = CellBuilder::new();
        builder.store_small_uint(0, 4)?;
        Tokens::ZERO.store_into(&mut builder, cx)?;
        owner.store_into(&mut builder, cx)?;
        master_addr.store_into(&mut builder, cx)?;
        merkle_root.store_into(&mut builder, cx)?;
        builder.build_ext(cx)?
    };

    CellBuilder::build_from_ext(
        StateInit {
            split_depth: None,
            special: None,
            code: Some(code),
            data: Some(data),
            libraries: Dict::new(),
        },
        cx,
    )
}

fn init_logger() {
    use std::io::IsTerminal;

    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::{fmt, EnvFilter, Layer};

    fn is_systemd_child() -> bool {
        #[cfg(target_os = "linux")]
        unsafe {
            libc::getppid() == 1
        }

        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    let fmt_layer = if is_systemd_child() {
        fmt::layer().without_time().with_ansi(false).boxed()
    } else if !std::io::stdout().is_terminal() {
        fmt::layer().with_ansi(false).boxed()
    } else {
        fmt::layer().boxed()
    };

    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();
}

fn serde_string<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: std::fmt::Display,
{
    serializer.collect_str(value)
}

const MAX_REQUEST_SIZE: usize = 32; // bytes
