import sys, os
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parent.parent))
os.environ.setdefault("ALLOW_INTERNAL", "true")
os.environ.setdefault("FASTMCP_MASK_ERROR_DETAILS", "false")
os.environ.setdefault("FASTMCP_STRICT_INPUT_VALIDATION", "false")
os.environ.setdefault("FASTMCP_LOG_LEVEL", "DEBUG")

from tools.mcp_service import mcp
import uvicorn

# Pure ASGI wrapper — intercepts GET /mcp before FastMCP sees it
class GetMcpMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            if scope["method"] == "GET" and scope["path"] == "/mcp":
                # Return 200 {} to satisfy AEX discovery probe
                await send({
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"allow", b"GET, POST"),
                        (b"content-length", b"2"),
                    ],
                })
                await send({
                    "type": "http.response.body",
                    "body": b"{}",
                })
                return

            if scope["method"] == "POST" and scope["path"] == "/mcp":
                # Inject Accept header required by FastMCP StreamableHTTP.
                # AEX does not send Accept: application/json, text/event-stream,
                # which FastMCP requires — without it requests are rejected with -32600.
                headers = [(k, v) for k, v in scope.get("headers", [])
                           if k.lower() != b"accept"]
                headers.append((b"accept", b"application/json, text/event-stream"))
                scope = dict(scope)
                scope["headers"] = headers

        await self.app(scope, receive, send)

fastmcp_app = mcp.http_app()
app = GetMcpMiddleware(fastmcp_app)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=6019, log_level="debug")
