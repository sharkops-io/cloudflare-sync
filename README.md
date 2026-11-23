# cloudflare-sync

Keeps a Cloudflare account in line with a config file. Run it on a schedule
(the Helm chart runs it as a CronJob, plus once on every deploy) and it:

- **finds a Cloudflare Tunnel by name, or creates it**, and sets its routes
  (ingress rules);
- optionally keeps **one proxied CNAME** pointing at the tunnel, so DNS records
  elsewhere can target a stable name instead of the tunnel's ID;
- optionally writes the tunnel's **run token to a Kubernetes Secret**, so
  `cloudflared` can run from it. A rebuilt cluster gets the token back on the
  first run, with nothing to restore;
- keeps the **custom WAF rules** and **rate-limiting rules** it owns on each zone;
- keeps the **Cloudflare Access applications** it owns, with their policies.

It does not manage DNS records for your applications. A tool such as
external-dns does that better, from the objects that define the routes.

It's one Python file using only the standard library, with no SDK.

## Desired state, with ownership

Every run compares what Cloudflare has with the config and changes only the
difference. A second run with the same config changes nothing.

Objects it creates carry a marker made from `owner` (default `cloudflare-sync`):

| Object | Marker |
|---|---|
| WAF and rate-limiting rules | description starts with `[owner] ` |
| Access applications | the Access tag `owner` (created if missing) |
| the alias CNAME | comment `managed by owner` |
| the tunnel | its name, from the config |

Objects **without** the marker are never changed or deleted: a rule someone
added in the dashboard stays, and each run lists it as left alone. Objects
**with** the marker that are no longer in the config are deleted. A hand edit
to an owned object is reverted on the next run, and the log says so.

If an object without the marker is in the way (a DNS record with the alias's
name, an Access application on a configured domain), that section fails and
nothing in the way is touched.

Two instances with different `owner` values can share an account or zone
without touching each other's objects.

## Config

JSON, or YAML through the Helm chart's `config` value. **Unknown keys are an
error**: a misspelt key fails the run instead of being silently skipped.
Each top-level section is managed only when it is present, so the API token
needs permissions only for the sections you use.

```yaml
accountId: 0123456789abcdef0123456789abcdef   # required
owner: cloudflare-sync                        # optional, the ownership marker

tunnel:
  name: edge                     # found by name; created if missing
  ingress:                       # in order; first match wins
    - hostname: "*.example.com"
      service: http://gateway.example.svc.cluster.local:80
      # path: ^/api            optional
      # originRequest: {...}   optional, as in the Cloudflare API
  catchAll: http_status:404      # optional, the last rule's service
  # originRequest: {...}         optional, defaults for every rule
  dnsAlias:                      # optional
    zone: example.com
    name: tunnel.example.com     # proxied CNAME -> <tunnel-id>.cfargotunnel.com
  tokenSecret:                   # optional; needs to run in Kubernetes
    name: cloudflared-token
    # key: token                 default
    # namespace: ...             default: the pod's own namespace

zones:
  - name: example.com
    customRules:                 # phase http_request_firewall_custom
      - description: block admin paths
        expression: '(http.request.uri.path contains "/admin")'
        action: block
    rateLimits:                  # phase http_ratelimit
      - description: login attempts
        expression: '(http.request.uri.path eq "/login")'
        action: block
        ratelimit:
          characteristics: [ip.src, cf.colo.id]
          period: 10
          requests_per_period: 20
          mitigation_timeout: 10

access:
  apps:                          # self-hosted applications
    - name: Dashboard
      domain: dash.example.com
      sessionDuration: 24h       # optional
      # settings: {...}          optional, any other application field
      policies:                  # in precedence order
        - name: staff
          decision: allow
          include:
            - email_domain: {domain: example.com}
          # exclude: [...]  require: [...]
```

Rule and policy bodies are passed to Cloudflare as written, so they use the
API's own field names (`action_parameters`, `requests_per_period`, `email_domain`).
Each rule needs a `description`, which becomes `[owner] <description>`.
Rules you own are placed after any rules you don't own in the same phase.
Cloudflare's plan limits apply: the Free plan allows a few custom rules and
one rate-limiting rule with a short `period`.

An empty list (`customRules: []`, `access: {apps: []}`) deletes everything the
owner has there. Leaving the key out leaves that part of Cloudflare alone.

## API token

Create a token with only what the sections you use need:

| Section | Permission |
|---|---|
| `tunnel` | Account · Cloudflare Tunnel · Edit |
| `tunnel.dnsAlias` | Zone · DNS · Edit, and Zone · Zone · Read |
| `zones` | Zone · Zone WAF · Edit, and Zone · Zone · Read |
| `access` | Account · Access: Apps and Policies · Edit |

Pass it as `CLOUDFLARE_API_TOKEN`, or as a file path in `CLOUDFLARE_API_TOKEN_FILE`.
The token is never logged, and neither is the tunnel's run token.

## Running it

```sh
python3 cloudflare_sync.py --config config.json --dry-run
python3 cloudflare_sync.py --config config.json
```

`--dry-run` (or `DRY_RUN=1`) reads everything, logs what it would change, and
sends nothing but GET requests. Add `--validate` (or `VALIDATE=1`) to also send
ruleset changes to Cloudflare with `?dry_run=true`, which Cloudflare's API
documents as "validates the request without persisting changes". That is
still a PUT, so it's off unless you ask for it.

Each section runs even if an earlier one failed. The exit status is `0` when
everything is in sync, `1` if any section failed, and `2` for a bad config or
missing token.

### Helm

```sh
helm install cloudflare-sync oci://ghcr.io/sharkops-io/charts/cloudflare-sync \
  --namespace tunnel --create-namespace -f values.yaml
```

```yaml
apiToken:
  existingSecret: cloudflare-api-token   # a Secret you create; key `token`
config:
  accountId: 0123456789abcdef0123456789abcdef
  tunnel:
    name: edge
    ingress:
      - hostname: app.example.com
        service: http://app.default.svc.cluster.local:80
    tokenSecret:
      name: cloudflared-token
cloudflared:
  enabled: true      # runs cloudflared x2 from that token
```

The chart deploys a CronJob (`schedule`, hourly by default) and a Job that
runs on every install and upgrade (`runOnDeploy`). If Cloudflare rejects the
config, the release fails. With `tunnel.tokenSecret` set, it also adds a Role
that can read and patch that one Secret and create Secrets in its namespace,
so give the tunnel a namespace of its own. With `cloudflared.enabled` it runs
`cloudflared` from the token. See [`chart/values.yaml`](chart/values.yaml) and
[`chart/examples`](chart/examples).

A failed run is a failed Job. Alert on that (for example kube-state-metrics'
`kube_job_failed`).

## Limits

- Only **remotely managed** tunnels (configured through the API). A tunnel run
  from a local config file is refused, not converted.
- Comparisons check only the fields the config sets, so the defaults Cloudflare
  adds don't count as drift. If you delete a key from an object in the config,
  that isn't seen as a change until something else in the object changes.
  Removing a whole rule, route or application is always seen.
- Only the rulesets endpoints offer server-side validation (`--validate`). For
  the tunnel, DNS and Access endpoints, a dry run only logs what it would send.

## Development

```sh
cd tests && python3 -m unittest -v          # the reconciler, against a fake API
helm unittest --strict -f 'tests/*.yaml' chart
```

The tests run the real HTTP client against in-process fakes of the Cloudflare
and Kubernetes APIs, shaped after Cloudflare's published OpenAPI schema.

## License

Apache-2.0
