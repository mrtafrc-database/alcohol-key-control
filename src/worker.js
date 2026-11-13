export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const json = (body, status = 200) =>
      Response.json(body, {
        status,
        headers: {
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff"
        }
      });

    if (request.method !== "GET") {
      return json({ ok: false, error: "Method not allowed" }, 405);
    }

    if (url.pathname !== "/health") {
      return json({ ok: false, error: "Not found" }, 404);
    }

    if (!env.DB) {
      return json({
        ok: false,
        error: "D1 binding DB is missing"
      }, 503);
    }

    try {
      const migration = await env.DB.prepare(
        "SELECT MAX(version) AS version FROM schema_migrations"
      ).first();

      if (Number(migration?.version) !== 1) {
        return json({
          ok: false,
          error: "Unexpected database schema version"
        }, 503);
      }

      return json({
        ok: true,
        service: "alcohol-key-control-api",
        database: "connected",
        schemaVersion: Number(migration.version)
      });
    } catch (error) {
      // Do not expose SQL errors or configuration details publicly.
      console.error("Database health check failed");

      return json({
        ok: false,
        error: "Database health check failed"
      }, 503);
    }
  }
};
