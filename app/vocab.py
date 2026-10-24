"""Fixed vocabularies. The LLM tool schema uses these as enums, so Claude
can only tag what the scoring model understands."""

SURFACES: dict[str, str] = {
    "http-parsing": "HTTP request/response parsing, headers, smuggling, keep-alive",
    "multipart-upload": "multipart/form-data, file upload handling, upload progress",
    "session-state": "session lifecycle, global/request state reuse across requests",
    "compression": "decompressors and codecs: gzip/deflate, brotli, zstd, lzma",
    "archive": "archive formats: zip, tar, rar, 7z, cab",
    "image-codec": "image decoding and transformation: webp, png, svg, tiff",
    "document-parser": "PDF, office, postscript, ASN.1, database file parsing",
    "xml": "XML parsing, entity expansion, XXE",
    "serialization": "object deserialization, unserialize, pickle, Java serialization",
    "dns": "DNS resolution, name parsing, response handling",
    "ip-canonicalization": "IP/hostname normalization, alternate encodings, SSRF filter bypass",
    "tls-validation": "certificate chain and hostname verification",
    "auth-session-reuse": "authenticated connection or credential reuse, auth bypass",
    "template-engine": "server-side templating, SSR, injection into render paths",
    "path-handling": "path traversal, normalization, symlink handling",
    "vpn-gateway": "SSL VPN and remote-access gateway pre-auth surface",
    "mgmt-plane": "appliance management interfaces and admin APIs",
    "kernel-network": "kernel or OS network stack, RPC services",
}

# Short plain-language names for the executive view.
SURFACE_LABELS: dict[str, str] = {
    "http-parsing": "HTTP parsing",
    "multipart-upload": "File upload",
    "session-state": "Session state",
    "compression": "Compression",
    "archive": "Archive formats",
    "image-codec": "Image decoding",
    "document-parser": "Document parsing",
    "xml": "XML parsing",
    "serialization": "Deserialization",
    "dns": "DNS",
    "ip-canonicalization": "IP / hostname parsing",
    "tls-validation": "TLS validation",
    "auth-session-reuse": "Auth & session reuse",
    "template-engine": "Templating",
    "path-handling": "Path handling",
    "vpn-gateway": "VPN gateway",
    "mgmt-plane": "Management plane",
    "kernel-network": "Kernel network stack",
}

EXPLOITATION = ("none", "attempts", "confirmed", "unknown")
