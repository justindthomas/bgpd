# bgpd

BGP-4 daemon (RFC 4271) that pushes best-path winners to [ribd](https://github.com/justindthomas/ribd) as recursive next-hops; ribd resolves them against the IGP RIB and programs the result into VPP / kernel.

## Scope

v1 RFC coverage: 4271, 4760 (MP-BGP v4/v6 unicast), 5492 (capabilities), 6793 (4-octet ASN), 2918 (route refresh), 7606 (treat-as-withdraw), 8212 (default-deny EBGP), 1997 (communities).

Explicitly deferred to v2: Graceful Restart, ADD-PATH, BMP, RPKI, BGP Roles.

## Build

```sh
cargo build --release
```

With the optional VCL feature (binds the BGP listener via VPP's VCL instead of the kernel TCP stack):

```sh
cargo build --release --features vcl
```

## Run

```sh
bgpd --config /etc/bgpd/config.yaml
```

Flags:

| Flag | Default | Purpose |
|------|---------|---------|
| `--config PATH` | `/etc/bgpd/config.yaml` | Config file |
| `--rib-socket PATH` | `/run/ribd.sock` | ribd Unix socket |
| `--control-socket PATH` | `/run/bgpd.sock` | Unix socket for `query` subcommands |
| `--vcl` | off | Use VCL-bound listener (requires `--features vcl`) |

`SIGHUP` re-reads the config and diffs without resetting established sessions.

## Query a running daemon

```sh
bgpd query summary
bgpd query neighbors
bgpd query routes
bgpd query advertised <peer-ip>
bgpd query received <peer-ip>
```

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).

If the AGPL's obligations are incompatible with your use, commercial licenses are available. See [CONTRIBUTING.md](CONTRIBUTING.md).
