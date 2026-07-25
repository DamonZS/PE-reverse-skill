from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DeploymentConfigTests(unittest.TestCase):
    def test_python_web_command_delegates_to_go_and_does_not_import_legacy_server(self) -> None:
        cli = (ROOT / "reverse_analyzer" / "cli.py").read_text(encoding="utf-8")
        self.assertNotIn("from .web_api import serve_web_console", cli)
        self.assertIn('"mode": "go-control-plane"', cli)

    def test_dockerfile_builds_frontend_and_serves_integrated_web_console(self) -> None:
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

        self.assertIn("FROM node:20-bookworm-slim AS frontend-builder", dockerfile)
        self.assertIn("RUN npm ci", dockerfile)
        self.assertIn("RUN npm run build", dockerfile)
        self.assertIn("FROM golang:1.26-bookworm AS go-builder", dockerfile)
        self.assertIn("go build", dockerfile)
        self.assertIn("-mod=vendor", dockerfile)
        self.assertIn("COPY --from=frontend-builder /src/frontend/dist ./frontend/dist", dockerfile)
        self.assertIn("COPY deploy/platform-entrypoint.sh /usr/local/bin/platform-entrypoint", dockerfile)
        self.assertIn('ENTRYPOINT ["platform-entrypoint"]', dockerfile)
        self.assertIn("HEALTHCHECK", dockerfile)
        self.assertIn("/api/health", dockerfile)

    def test_compose_defaults_to_loopback_web_exposure(self) -> None:
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

        self.assertIn("reverse-analyzer-web:", compose)
        self.assertIn("\"127.0.0.1:8090:8090\"", compose)
        self.assertIn("REVERSE_ANALYZER_FRONTEND_DIR", compose)
        self.assertIn("REVERSE_ANALYZER_WEB_TOKEN", compose)
        self.assertIn("/app/frontend/dist", compose)
        self.assertIn("/api/health", compose)

    def test_deployment_doc_warns_against_public_exposure_without_auth(self) -> None:
        doc = (ROOT / "docs" / "web-deployment.md").read_text(encoding="utf-8")

        self.assertIn("\u4e0d\u8981\u76f4\u63a5\u628a 8090 \u66b4\u9732\u5230\u516c\u7f51", doc)
        self.assertIn("\u5f53\u524d\u9879\u76ee\u6ca1\u6709\u5185\u7f6e\u751f\u4ea7\u7ea7\u767b\u5f55\u8ba4\u8bc1", doc)
        self.assertIn("\u663e\u5f0f\u786e\u8ba4", doc)
        self.assertIn("\u7ba1\u7406\u5458\u5f15\u5bfc\u4ee4\u724c", doc)


if __name__ == "__main__":
    unittest.main()
