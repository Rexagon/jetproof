## jetproof

A tool for creating huge jetton offchain merkle proofs.

### Installation

```bash
# Only csv:
cargo install jetproof --locked
# Or a full version:
cargo install jetproof --locked --features api
```

### Requirements

This tool is mostly IO-bound. It takes around **20s** to build a full dictionary for **30M** entries (while eating up to **13GB** of RAM). However, it will then spend some time generating and writing proofs list to the file.

### Usage

```
Build merkle proofs from a csv file

Usage: jetproof build [OPTIONS] --type <TY> <INPUT> [OUTPUT]

Arguments:
  <INPUT>   path to the csv file (address, amount)
  [OUTPUT]  path to the output csv file (address, proof) or a RocksDB directory

Options:
  -t, --type <TY>
          output type (csv, api). (default: csv)
      --claim-function-id <CLAIM_FUNCTION_ID>
          build airdrop claim payload with this id instead of raw proofs
      --start-from <START_FROM>
          a unix timestamp when the airdrop starts. (default: now)
      --expire-at <EXPIRE_AT>
          a unix timestamp when the airdrop ends. (default: never)
  -f, --force
          overwrite the output if it exists
  -q, --quiet
          hide the progress bar
  -h, --help
          Print help
```

---

```bash
jetproof build test.csv test.out.csv --type csv
```

Example output (`stdout`):
```json
{
  "dict_root": "c9e1b072c0599baa4251c6b592e7ec8370cb6369fd3e2365188de982b782cc9a",
  "start_from": 1725031234,
  "expire_at": 281474976710655
}
```

> Note: you can omit the output path for a dry run.

### Input CSV

Item: `address`, `amount` (integer values, multiplied by 10^9)

Example:
```csv
0:6d832edf6c5016228e8f099327d59f753fa726f82c38011a4eaaff4434e2b2c1,41401000000000
0:200dcfd1241e45cb348c87e5f6f89cf0f9084c6f82df9c8dfe21d08cce59c76e,20079000000000
0:626b72139cf6e7313df4b9d63a5513c2d999f4ca3f68fd80818e1e36e83edb82,17113000000000
0:8540c37e0afb0a88d649d5b7837438956b9a3781c79f729f1c151638b8e0ad53,23345000000000
0:7a8663ec20267ff88d86d322e1af7d0b222edd37642f40cd06ea7b916cf69a61,42360000000000
```

### Output CSV

Item: `address`, `proof` (base64 encoded)

Example:
```csv
0:200dcfd1241e45cb348c87e5f6f89cf0f9084c6f82df9c8dfe21d08cce59c76e,te6ccgEBBgEAxAAJRgMjbQR1axRsv9z2YZvPuksRDWNpty/IJYu1IEPtcQIsuQAEASIFgXACAwIAZ7/CoGG/BX2FRGsk6tvBuhxKtc0bwOPPuU+OCoscXHBWqbCp23N1UAAAAzaO/q////////wiASAFBChIAQFlI23AGxTj5J/EG9iovfiMcnCfqUX1lDEvy2Jx99SdiAACAGe/oA3P0SQeRcs0jIfl9vic8PkITG+C35yN/iHQjM5Zx25hJDAamWAAAAZtHf1f///////4
0:626b72139cf6e7313df4b9d63a5513c2d999f4ca3f68fd80818e1e36e83edb82,te6ccgECCgEAAUoACUYDI20EdWsUbL/c9mGbz7pLEQ1jabcvyCWLtSBD7XECLLkABAECBYFwAgMCAGe/wqBhvwV9hURrJOrbwbocSrXNG8Djz7lPjgqLHFxwVqmwqdtzdVAAAAM2jv6v///////8AgEgCQQCAVgGBQBnvyoZj7CAmf/iNhtMi4a99CyIu3TdkL0DNBup7kWz2mmFiaGtMCwAAAAZtHf1f///////4AIBIAgHAGe+7Bl2+2KAsRR0eEyZPqz7qf05N8FhwAjSdVf6IacVlgsS07Xy/QAAADNo7+r////////AAGe+01uQnOe3OYnvpc6x0qieFszPplH7R+wEDHDxt0H23BMHyDcknQAAADNo7+r////////AAGe/oA3P0SQeRcs0jIfl9vic8PkITG+C35yN/iHQjM5Zx25hJDAamWAAAAZtHf1f///////4
0:6d832edf6c5016228e8f099327d59f753fa726f82c38011a4eaaff4434e2b2c1,te6ccgECCgEAAUoACUYDI20EdWsUbL/c9mGbz7pLEQ1jabcvyCWLtSBD7XECLLkABAECBYFwAgMCAGe/wqBhvwV9hURrJOrbwbocSrXNG8Djz7lPjgqLHFxwVqmwqdtzdVAAAAM2jv6v///////8AgEgCQQCAVgGBQBnvyoZj7CAmf/iNhtMi4a99CyIu3TdkL0DNBup7kWz2mmFiaGtMCwAAAAZtHf1f///////4AIBIAgHAGe+7Bl2+2KAsRR0eEyZPqz7qf05N8FhwAjSdVf6IacVlgsS07Xy/QAAADNo7+r////////AAGe+01uQnOe3OYnvpc6x0qieFszPplH7R+wEDHDxt0H23BMHyDcknQAAADNo7+r////////AAGe/oA3P0SQeRcs0jIfl9vic8PkITG+C35yN/iHQjM5Zx25hJDAamWAAAAZtHf1f///////4
0:7a8663ec20267ff88d86d322e1af7d0b222edd37642f40cd06ea7b916cf69a61,te6ccgEBCAEA/wAJRgMjbQR1axRsv9z2YZvPuksRDWNpty/IJYu1IEPtcQIsuQAEASIFgXACAwIAZ7/CoGG/BX2FRGsk6tvBuhxKtc0bwOPPuU+OCoscXHBWqbCp23N1UAAAAzaO/q////////wiASAHBCIBWAYFAGe/KhmPsICZ/+I2G0yLhr30LIi7dN2QvQM0G6nuRbPaaYWJoa0wLAAAABm0d/V////////gKEgBASNqM3VvMEzjibdCw9Vo4NW31wCTzAI7za95XpklpZihAAEAZ7+gDc/RJB5FyzSMh+X2+Jzw+QhMb4LfnI3+IdCMzlnHbmEkMBqZYAAABm0d/V////////g=
0:8540c37e0afb0a88d649d5b7837438956b9a3781c79f729f1c151638b8e0ad53,te6ccgEBBAEAiQAJRgMjbQR1axRsv9z2YZvPuksRDWNpty/IJYu1IEPtcQIsuQAEASIFgXACAwIAZ7/CoGG/BX2FRGsk6tvBuhxKtc0bwOPPuU+OCoscXHBWqbCp23N1UAAAAzaO/q////////woSAEBXdNnv87Bwf3QIjIyGIV8PVp+PQ9U1XGPYDEh9H+OomQAAw==
```

### API

This tool has a powerful built-in API to serve proofs in accordance with [this TEP](https://github.com/tonkeeper/TEPs2/blob/custom-payload/text/0000-jetton-offchain-payloads.md).

> Note: make sure to install it with the `api` feature.

```
# Install
cargo install jetproof --locked --features api

# Build the db
jetproof build test.csv ./db --type api

# Prepare env
export JETPROOF_LISTEN_ADDR=0.0.0.0:8081
export JETPROOF_STORAGE_PATH=./db
export JETPROOF_MASTER_ADDR=0:0000000000000000000000000000000000000000000000000000000000000000
export JETPROOF_WALLET_CODE=b5ee9c7241020f01000380000114ff00f4a413f4bcf2c80b01020162050202012004030021bc508f6a2686981fd007d207d2068af81c0027bfd8176a2686981fd007d207d206899fc152098402f8d001d0d3030171b08e48135f038020d721ed44d0d303fa00fa40fa40d104d31f01840f218210178d4519ba0282107bdd97deba12b1f2f48040d721fa003012a0401303c8cb0358fa0201cf1601cf16c9ed54e0fa40fa4031fa0031f401fa0031fa00013170f83a02d31f012082100f8a7ea5ba8e85303459db3ce0330c06025c228210178d4519ba8e84325adb3ce034218210595f07bcba8e843101db3ce0135f038210d372158cbadc840ff2f0080701f2ed44d0d303fa00fa40fa40d106d33f0101fa00fa40f401d15141a15238c705f2e04926c2fff2afc882107bdd97de01cb1f5801cb3f01fa0221cf1658cf16c9c8801801cb0526cf1670fa02017158cb6accc903f839206e943081169fde718102f270f8380170f836a0811a6570f836a0bcf2b0028050fb00030903e6ed44d0d303fa00fa40fa40d107d33f0101fa005141a004fa40fa4053bac705f82a5464e070546004131503c8cb0358fa0201cf1601cf16c921c8cb0113f40012f400cb00c9f9007074c8cb02ca07cbffc9d0500cc7051bb1f2e04a09fa0021925f04e30d26d70b01c000b393306c33e30d55020b0a09002003c8cb0358fa0201cf1601cf16c9ed54007a5054a1f82fa07381040982100966018070f837b60972fb02c8801001cb055005cf1670fa027001cb6a8210d53276db01cb1f5801cb3fc9810082fb00590060c882107362d09c01cb1f2501cb3f5004fa0258cf1658cf16c9c8801001cb0524cf1658fa02017158cb6accc98011fb0001f603d33f0101fa00fa4021fa4430c000f2e14ded44d0d303fa00fa40fa40d1521ac705f2e0495115a120c2fff2aff82a54259070546004131503c8cb0358fa0201cf1601cf16c921c8cb0113f40012f400cb00c920f9007074c8cb02ca07cbffc9d004fa40f401fa002020d70b009ad74bc00101c001b0f2b19130e20d01fec88210178d451901cb1f500a01cb3f5008fa0223cf1601cf1626fa025007cf16c9c8801801cb055004cf1670fa024063775003cb6bccccc945372191729171e2f839206e938123399120e2216e94318128099101e25023a813a0738103a370f83ca00270f83612a00170f836a07381040982100966018070f837a0bcf2b0040e002a8050fb005803c8cb0358fa0201cf1601cf16c9ed548b4b6c49
# Optional:
export JETPROOF_STORAGE_CACHE=1gib

# Start the API
jetproof api
```

### License

Jetproof is available under the MIT license. See the LICENSE file for more info.
