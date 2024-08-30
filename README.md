## jetproof

A tool for creating huge jetton offchain merkle proofs.

### Installation

```bash
cargo install jetproof --locked
```

### Requirements

This tool is mostly IO-bound. It takes around **20s** to build a full dictionary for **30M** entries (while eating up to **13GB** of RAM). However, it will then spend some time generating and writing proofs list to the file.

### Usage

```
Usage: jetproof build <input> <output> [--start-from <start-from>] [--expire-at <expire-at>]

Build merkle proofs from a csv file.

Positional Arguments:
  input             path to the csv file (address, amount).
  output            path to the output csv file (address, proof).

Options:
  --start-from      a unix timestamp when the airdrop starts. (default: now)
  --expire-at       a unix timestamp when the airdrop ends. (default: never)
  --help            display usage information
```

---

```bash
jetproof build test.csv test.out.csv
```

Example output (`stdout`):
```json
{
  "dict_root": "c9e1b072c0599baa4251c6b592e7ec8370cb6369fd3e2365188de982b782cc9a",
  "start_from": 1725031234,
  "expire_at": 281474976710655
}
```

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

### License

Jetproof is available under the MIT license. See the LICENSE file for more info.
