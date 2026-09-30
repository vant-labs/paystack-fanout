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
        crate::app::bulk_replay,
        crate::app::list_admin_routes,
        crate::app::create_admin_route,
        crate::app::update_admin_route,
        crate::app::delete_admin_route,
        crate::app::list_admin_deliveries,
        crate::app::list_admin_settings,
        crate::app::set_admin_setting,
        crate::app::delete_admin_setting,
        crate::app::bootstrap_admin
    ),
    components(
        schemas(
            crate::db::EventSummary,
            crate::db::EventDetail,
            crate::db::AttemptView,
            crate::db::DatabaseRoute,
            crate::db::DatabaseRouteResponse,
            crate::db::DeliveryView,
            crate::db::SettingView,
            crate::app::ReplayBody,
            crate::app::RouteWriteBody,
            crate::app::SettingWriteBody,
            crate::app::BootstrapBody
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
