# Configuration

## Authentication

The collector uses a GravityZone API key over HTTP Basic auth (API key as username, empty
password), per GravityZone's [Public API](https://www.bitdefender.com/business/support/en/77209-125277-public-api.html)
convention.

```yaml
collectors:
  bitdefender:
    source: locktivity/epack-collector-bitdefender@^0.1
    config:
      base_url: https://cloud.gravityzone.bitdefender.com/api
      level: audit
    secrets:
      - BITDEFENDER_API_KEY
```

### Creating an API Key

1. Log in to GravityZone Control Center with an administrator account
2. Click your username (top right) > **My Account**
3. Go to the **API keys** section and click **Add**
4. Give it a description and select the APIs it can use — see
   [Required GravityZone APIs](#required-gravityzone-apis) below for exactly which ones
5. Click **Generate**, copy the key immediately (it's shown only once), and store it
   somewhere your secrets manager can read it as `BITDEFENDER_API_KEY`

### Region / on-premises base URLs

| Deployment | `base_url` |
|---|---|
| Global/US cloud | `https://cloud.gravityzone.bitdefender.com/api` |
| EU cloud | `https://cloudgz.gravityzone.bitdefender.com/api` |
| On-premises | Your Control Center's own API URL |

## Configuration Options

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `base_url` | string | Yes | - | GravityZone Control Center API base URL |
| `parent_group_id` | string | No | company root | Scope collection to one network group (and descendants) instead of the whole company |
| `level` | string | No | `trust` | Collection level: `trust`, `audit`, or `internal` |

## Secrets

| Name | Required | Description |
|------|----------|--------------|
| `BITDEFENDER_API_KEY` | Yes | GravityZone API key, used as the HTTP Basic auth username |

## Required GravityZone APIs

Each API key is scoped to specific APIs at creation time. Grant only what the configured
level needs — a missing API skips just that surface (recorded under
`diagnostics.permission_errors`), so you can grant incrementally.

| Surface | Gating API | Needed for |
|---------|-----------|------------|
| Compliance %, endpoint inventory | **Network** | trust / audit / internal |
| Per-endpoint policy + enabled modules | **Network** | internal |
| Quarantine inventory | **Quarantine** | internal |

`trust` and `audit` only ever need the Network API.

## Troubleshooting

**"base_url is required"**

Set `base_url` in your config — see [Region / on-premises base URLs](#region--on-premises-base-urls)
above.

**"authentication required"**

Provide `BITDEFENDER_API_KEY` as a secret.

**GravityZone JSON-RPC error `-32001` ("Authorization error")**

The API key isn't scoped to the API the call needed. Add that API to the key under
**My Account > API keys** in Control Center — see
[Required GravityZone APIs](#required-gravityzone-apis) above. The collector surfaces this
as a `permission_errors` diagnostic entry rather than failing the whole run, except for the
initial endpoint list call (Network API), which is required at every level.

**GravityZone JSON-RPC error `-32003` / HTTP 429 ("Too many requests")**

GravityZone rate-limits API keys to a fixed number of requests per second. This collector
doesn't currently retry on rate limiting — if you hit it consistently (e.g. a very large
fleet at `internal` level, which calls `getManagedEndpointDetails` once per computer),
consider narrowing `parent_group_id` or running at `audit` instead.
