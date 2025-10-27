from html import escape

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

app = FastAPI()
templates = Jinja2Templates(directory="app/templates")


SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Referrer-Policy": "no-referrer",
}

CACHE_CONTROL_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Expires": "0",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        for header, value in CACHE_CONTROL_HEADERS.items():
            response.headers.setdefault(header, value)
        return response


app.add_middleware(SecurityHeadersMiddleware)


@app.get("/", response_class=HTMLResponse)
def index(request: Request, q: str = ""):
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "q": q},
    )


@app.get("/healthz")
def healthz():
    return PlainTextResponse("OK")


@app.get("/echo", response_class=HTMLResponse)
def echo(x: str = ""):
    safe_body = "<h1>ECHO</h1><div>you said: {}</div>".format(escape(x, quote=True))
    return HTMLResponse(safe_body)
