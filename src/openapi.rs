use utoipa::openapi::security::{Http, HttpAuthScheme, SecurityScheme};
use utoipa::{Modify, OpenApi};

struct BearerAuth;

impl Modify for BearerAuth {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let scheme = SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer));
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme("admin_bearer", scheme);
        } else {
            openapi.components = Some(
                utoipa::openapi::ComponentsBuilder::new()
                    .security_scheme("admin_bearer", scheme)
                    .build(),
            );
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::app::ingest,
        crate::app::healthz,
        crate::app::readyz,
        crate::app::metrics,
        crate::app::list_events,
        crate::app::get_event,
        crate::app::replay_event,
        crate::app::bulk_replay
    ),
    components(
        schemas(
            crate::db::EventSummary,
            crate::db::EventDetail,
            crate::db::AttemptView,
            crate::app::ReplayBody
        )
    ),
    modifiers(&BearerAuth),
    tags(
        (name = "Webhook", description = "Paystack webhook ingestion"),
        (name = "Operations", description = "Health and Prometheus endpoints"),
        (name = "Admin API", description = "Bearer-protected event operations")
    ),
    info(
        title = "paystack-fanout API",
        version = "0.1.0",
        description = "Durable Paystack webhook ingestion and delivery API"
    )
)]
pub struct ApiDoc;
