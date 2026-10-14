# Apple App Store setup

This service uses the existing fanout ingest, deduplication, outbox, delivery
queue, and normalized event contract. Configure one source per Apple
environment; do not send sandbox notifications or receipts to a production
source.

## Prerequisites

- An App Store app with the bundle ID and in-app purchase products configured.
- An HTTPS endpoint reachable by App Store Server Notifications V2:
  `https://your-host/in/apple_production` or
  `https://your-host/in/apple_sandbox`.
- An App Store Connect API key when server-side transaction lookups are
  enabled: issuer ID, key ID, and the private key.
- A product-to-licence mapping in the source configuration.

The Apple root certificate used to validate the JWS `x5c` chain is bundled at
`src/certs/apple/AppleRootCA-G3.cer`. Notification payloads are accepted only
when the signed bundle ID and environment match the source configuration.

## Production source

Add a source in the dashboard or use the first-boot configuration seed:

```toml
[source.apple_production]
provider = "apple_server_notifications"
secret_env = "APPLE_API_PRIVATE_KEY"

[source.apple_production.provider_config]
app_identifier = "com.example.timamu"
environment = "production"
api_base_url = "https://api.storekit.itunes.apple.com"
key_id_env = "APPLE_API_KEY_ID"
issuer_id_env = "APPLE_API_ISSUER_ID"
private_key_env = "APPLE_API_PRIVATE_KEY"
"product_licence.com.example.timamu.monthly" = "timamu_pro"
```

`secret_env` is retained for configuration compatibility. The API key values
must be supplied through secrets; do not commit the private key. The
`product_licence.<product-id>` entries are the only product-to-licence mapping
used by the adapter.

Create a separate sandbox source by changing the source name, route URL,
`environment = "sandbox"`, and `api_base_url` to
`https://api.storekit-sandbox.itunes.apple.com`.

## App Store Connect configuration

1. Configure App Store Server Notifications V2 for the app.
2. Use the matching source URL as the production or sandbox notification URL.
3. Configure a route with the same `app_identifier` and `environment` values.
4. Confirm that the source can reach the configured Apple API endpoint when
   purchase verification or reconciliation is enabled.

The adapter verifies the outer `signedPayload` and the signed transaction,
then maps subscription changes to the normalized `purchase`, `renew`,
`expire`, `grace`, `refund`, `revoke`, `upgrade`, or `downgrade` events.
Notification UUIDs and transaction identities are deduplicated by the
provider-agnostic event store.

## Client verification

The client sends the receipt or signed transaction to the server:

```http
POST /v1/purchases/verify
Authorization: Bearer <account-JWT>
Content-Type: application/json

{"provider":"apple","receipt":"<signed-transaction-JWS>"}
```

The bearer identity must contain the account in `sub` or `account_id`. The
Apple `appAccountToken` must match that verified account. Account IDs supplied
in the body, query string, or `X-Timamu-Account-Id` header are not trusted.
The app reads `GET /v1/entitlements` with the same bearer token and never
grants access from a local receipt check.

Set `PURCHASE_JWT_SECRET` for HS256 account JWTs, or set
`PURCHASE_BEARER_TOKEN` and `PURCHASE_BEARER_ACCOUNT_ID` for a static
account-bound bearer identity.

## References

- [Apple PKI](https://www.apple.com/certificateauthority/)
- [App Store Server Notifications](https://developer.apple.com/documentation/appstoreservernotifications)
- [App Store Server API](https://developer.apple.com/documentation/appstoreserverapi)
- [Signed payload format](https://developer.apple.com/documentation/appstoreserverapi/signedpayload)
