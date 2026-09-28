from playwright.sync_api import expect, sync_playwright


with sync_playwright() as playwright:
    browser = playwright.chromium.launch()
    page = browser.new_page()
    page.goto("http://127.0.0.1:8080/login")
    page.get_by_label("Email").fill("owner@example.com")
    page.get_by_label("Password").fill("long secure password")
    page.get_by_role("button", name="Sign in").click()
    expect(page).to_have_url("http://127.0.0.1:8080/admin")

    page.goto("http://127.0.0.1:8080/dashboard/events?status=pending")
    expect(page.get_by_text("Event ledger")).to_be_visible()
    event_link = page.locator("a.event-id").first
    if event_link.count():
        event_link.click()
        expect(page.get_by_text("Original payload")).to_be_visible()
        page.locator("form[action$='/replay'] input[name=route]").fill("timamu")
        page.locator("form[action$='/replay'] button").click()

    page.goto("http://127.0.0.1:8080/dashboard/events")
    with page.expect_download() as download:
        page.get_by_text("Export CSV").click()
    assert download.value.suggested_filename == "fanout-events.csv"
    browser.close()
