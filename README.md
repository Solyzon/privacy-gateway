<div align="center">
  <h1>privacy-gateway</h1>

  <p>A local proxy that hides your secrets and personal data from the model before Claude Code or Codex sends them, and puts them back in the answer.</p>

  <p>
    <img alt="Go" src="https://img.shields.io/badge/Go-1.26-00ADD8?style=flat-square&logo=go&logoColor=white">
    <img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square">
  </p>
</div>

## Why

A coding agent reads your `.env`, your database dumps and your logs, and all of it goes to the
model provider. privacy-gateway sits on `127.0.0.1:8787` between the agent and the API. Every
secret or personal value in the request becomes a stable placeholder, and the streamed answer
gets the real value back, including inside the commands the agent runs.

```text
what you have     | 42 | Mme Claire Dubois | +33 6 12 34 56 78 |
what the model    | 42 | Mme Claire Dubois | SZ_PHONE_5c90a3e1b6d2 |
what you read     | 42 | Mme Claire Dubois | +33 6 12 34 56 78 |
```

## What it masks

| Kind      | Examples                                                                                                                                                                                                                 |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `SECRET`  | Anthropic, OpenAI, Stripe, GitLab, GitHub, AWS and Slack keys, JWTs, PEM private keys, URL passwords, values of `*_PASSWORD`, `*_TOKEN`, `*_SECRET`, `*_API_KEY` variables, `password` and `token` keys in YAML and JSON |
| `ADDRESS` | postal addresses in address fields, and a number followed by a street type in text                                                                                                                                       |
| `EMAIL`   | every address except technical mailboxes (`root`, `git`, `postgres`) and example domains                                                                                                                                 |
| `PHONE`   | French numbers and international numbers starting with `+`                                                                                                                                                               |
| `IBAN`    | every country, mod 97 checked                                                                                                                                                                                            |
| `CARD`    | Luhn checked                                                                                                                                                                                                             |
| `NIR`     | French social security numbers, key checked                                                                                                                                                                              |

People's names are not masked. Everything above is.

A placeholder is an HMAC-SHA256 of the value with a 32-byte key that never leaves the machine,
so the same value always gives the same placeholder. The JSON body is rewritten in place, keeping
key order and escapes, so the provider's prompt cache keeps hitting.

## Install

From the latest release, on macOS or Linux, Intel or ARM:

```bash
os=$(uname -s | tr A-Z a-z); arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
curl -fsSLo privacy-gateway "https://github.com/Solyzon/privacy-gateway/releases/latest/download/privacy-gateway-$os-$arch"
chmod +x privacy-gateway && ./privacy-gateway install
```

Each release lists the `SHA256SUMS` of its binaries. From source, with Go 1.26 or later:

```bash
git clone https://github.com/Solyzon/privacy-gateway.git
cd privacy-gateway
make install
```

`make install` builds the binary and runs `privacy-gateway install`. Either way, `install`:

- copies the binary to `~/.solyzon/privacy-gateway/bin/`;
- registers a `launchd` agent on macOS or a `systemd --user` unit on Linux;
- waits for `/healthz`;
- only then sets `ANTHROPIC_BASE_URL=http://127.0.0.1:8787` in `~/.claude/settings.json`, and
  points `model_provider` of `~/.codex/config.toml` at the gateway when Codex is installed.

Restart your open Claude Code sessions so they pick up the new setting.

## Check and remove

```bash
privacy-gateway status    # one-line summary
privacy-gateway audit     # exits 1 on any gap: service down, setting missing, canary leaking, agent talking to the API directly
privacy-gateway uninstall # removes the setting first, then the service
```

If the binary is gone, remove `ANTHROPIC_BASE_URL` from `env` in `~/.claude/settings.json`.

## Limits

- Images and PDFs are sent as they are. The status line says so for each new attachment.
- Names, an address without a number, and short passwords outside a known form stay readable.
- The model only sees the placeholder, so it cannot judge a value, for example a password's
  strength.
- When the gateway is down, the agent fails to connect. Nothing goes out in clear.

## Development

```bash
make verify    # gofmt, go vet, go test
make dev       # test gateway on 127.0.0.1:8788, without touching your settings
make live      # real run with Claude Code behind a recorder, uses a little Anthropic quota
```

## Contributing

Issues and pull requests are welcome, see [CONTRIBUTING.md](./CONTRIBUTING.md).

## Authors

Designed and built by **[Armand OCTEAU](https://github.com/Pomme978)** and
**[Sarah LÉVY](https://github.com/Saaaraaah14)** at [Solyzon](https://solyzon.com), since
October 2026.

## License

Copyright 2026 Solyzon. Licensed under the [Apache License, Version 2.0](./LICENSE).
