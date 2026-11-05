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
| `base_url` | string | Yes | - | GravityZone Control Center API base URL, starting with `https://` |
| `parent_group_id` | string | No | company root | Scope collection to one network group (and descendants) instead of the whole company |
| `level` | string | No | `trust` | Collection level: `trust`, `audit`, or `internal` |
| `collect` | list | No | every kind | Kinds of evidence to collect: `details` for `artifacts/bitdefender.details.json`, `endpoint-posture` for `artifacts/bitdefender.endpoint-posture.json` |

## Secrets

| Name | Required | Description |
|------|----------|--------------|
| `BITDEFENDER_API_KEY` | Yes | GravityZone API key, used as the HTTP Basic auth username |

## Required GravityZone APIs

Each API key is scoped to specific APIs at creation time. Grant only what the configured
level needs. A missing API leaves just that surface out, with a `permission_denied` gap in
`artifacts/bitdefender.collector-result.json` and an entry under
`diagnostics.permission_errors`, so you can grant incrementally.

| Surface | Gating API | Calls | Needed for |
|---------|-----------|-------|------------|
| Compliance %, endpoint inventory | **Network** | `getEndpointsList`, `getNetworkInventoryItems` | trust / audit / internal |
| Endpoint posture (`endpoint-posture`) | **Network** | `getManagedEndpointDetails` | trust / audit / internal |
| Per-endpoint policy + enabled modules | **Network** | `getManagedEndpointDetails` | internal |
| Quarantine inventory | **Quarantine** | `getQuarantineItemsList` | internal |

`trust` and `audit` only ever need the Network API. The collector reads the computers in
the Active Directory folder with `getNetworkInventoryItems`. In the collector result, a
gap's `missing_permission` is `network` or `quarantine`. These are the API names
`getApiKeyDetails` lists in the key's `enabledApis`.

## Troubleshooting

**"base_url is required"**

Set `base_url` in your config — see [Region / on-premises base URLs](#region--on-premises-base-urls)
above.

**"base_url must be an https URL"**

The API key travels in every request, so `base_url` must start with `https://` and name a
host.

**"authentication required"**

Provide `BITDEFENDER_API_KEY` as a secret.

**Exit code 3 with `auth_failed`**

GravityZone rejected the API key: HTTP 401, or an authorization error from
`getApiKeyDetails`, the first call, which needs no API enabled on the key. Check that the
key is current and copied whole.

**"parent_group_id ... is not a group GravityZone can find"** (exit code 2)

GravityZone answered that the group does not exist or the key's user cannot see it. Copy
the group ID from Control Center again, or remove `parent_group_id` to collect the whole
company.

**GravityZone JSON-RPC error `-32001` ("Authorization error")**

The API key isn't scoped to the API the call needed. Add that API to the key under
**My Account > API keys** in Control Center (see
[Required GravityZone APIs](#required-gravityzone-apis) above). The collector leaves the
values that call feeds out, with a `permission_denied` gap and a `permission_errors`
diagnostic entry, rather than failing the whole run.

**`scope.discovery_complete` is false or null in `artifacts/bitdefender.endpoint-posture.json`**

The collector could not read `getEndpointsList` or the Active Directory folder in full. It
is false when a list holds more than the 50,000 endpoints the collector reads. It is null
when a call failed, and the collector result has that call's code. The fleet counts and
protection percentages are left out, and so are the detailed file's computer count and
compliance values.

**GravityZone JSON-RPC error `-32003` / HTTP 429 ("Too many requests")**

GravityZone rate-limits API keys to a fixed number of requests per second. The collector
retries each call up to five times, whether the error comes with HTTP 429 or HTTP 200,
waiting as long as GravityZone's `Retry-After` header asks, up to 60 seconds. If
GravityZone is still throttling, the values that call feeds are left out with a
`rate_limited` gap. The collector calls `getManagedEndpointDetails` once per computer with
the agent at every level, so a very large fleet can hit it. If you hit it consistently, consider
narrowing `parent_group_id`, or set `collect: [details]` at `trust` or `audit` to skip
those calls.

**GravityZone JSON-RPC error `-32000` ("Server error")**

GravityZone failed while answering. The collector retries the call up to five times, as it
does an HTTP 5xx response. If the error persists, the values that call feeds are left out
with a `vendor_error` gap.
