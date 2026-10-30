# AI configuration repair for final-update

Chat and Q-Patch now read the same backend configuration from `.env` beside `dashboard.py` or from shell environment variables. Shell variables take priority; restart the server after changing configuration. No real key is stored in this branch.

The original Q-Patch adapter ignored `QSHIELD_AI_BASE_URL` and always called OpenAI's `/v1/responses`, even though chat supported a custom base URL. It also ignored the chat key/model aliases. This could send a gateway key to the wrong API host. Both features now share configuration, endpoint validation, bounded transport and safe HTTP diagnostics. The project `.env` parser handles UTF-8 BOM, `export`, quoted values and trailing comments.

## Setup

1. Copy `.env.example` to `.env` in this checkout.
2. Use a new key from the intended provider. Revoke any key shared in chat or committed elsewhere.
3. Set the provider's exact base URL and model ID. Do not guess the host from the key's prefix.
4. Restart `python dashboard.py` and inspect `/api/ai/status`. `configured` means settings are present; `connection_verified: false` explicitly says the status endpoint has not authenticated them.

For official OpenAI, keep `QSHIELD_AI_PROVIDER=openai` and its official base URL. For an OpenAI-compatible gateway, set:

```dotenv
OPENAI_API_KEY=your_new_provider_key
QSHIELD_AI_PROVIDER=agentrouter
QSHIELD_AI_BASE_URL=https://YOUR_CONFIRMED_PROVIDER_HOST/v1
QSHIELD_AI_MODEL=EXACT_MODEL_ID_FROM_YOUR_PROVIDER
QSHIELD_AI_API=chat_completions
QSHIELD_AI_TIMEOUT=30
```

`openai-compatible` is also accepted as the provider. Gateways require an explicit base URL: no automatic discovery or host fallback sends credentials elsewhere. HTTPS is required except for loopback development; embedded URL credentials, query strings and fragments are rejected. Redirects are refused.

AgentRouter-branded services have different hosts. The [agentrouter-org guide](https://github.com/agentrouter-org/docs/blob/main/qwencode.md) documents `https://agentrouter.org/v1`; a [separate AgentRouter portal](https://co.agentrouter.org/portal/guide) documents `https://co.agentrouter.org/v1`. These examples do not establish which service issued a particular key. Verify the dashboard used to create your key before selecting an endpoint.

Chat calls `/chat/completions`. Q-Patch defaults to `/responses` for `openai`, and `/chat/completions` for `agentrouter`/`openai-compatible`; `QSHIELD_AI_API` can explicitly select either. Q-Patch requires strict JSON-schema structured output support. A gateway supporting ordinary chat alone does not prove Q-Patch compatibility, and no silent protocol fallback is attempted.

## Errors and checks

- HTTP401: key inactive or issued for a different API host.
- HTTP403: provider/account/model permission denied.
- HTTP404: incorrect base URL, endpoint protocol or model ID.
- HTTP429: provider quota or rate limits; check balance and limits.
- Connection/timeout errors: verify the configured host and network.

Provider bodies and credentials are excluded from errors. Automated tests use fixture keys and controlled transport responses. Live credentials belong only in the ignored backend .env or process environment, never in Git. Authentication at one service does not establish compatibility with another service or its model APIs.

```sh
python -m unittest test_ai_configuration test_ai_advisor test_q_patch -v
```

## Verify the backend connection

```sh
python tools/check_ai_connection.py
```

This uses the same backend settings and performs only `GET /models`, with no text generation or scan-data sharing. It returns safe fields including `connection_verified`, `model_available`, `http_status` and a recognized provider error code. The process exits nonzero when configuration, authentication or model listing fails. A successful check does not prove generation quota or structured-output support.

In the AI tab, click **Test AI connection** for the same check. Startup status only means settings are present; it no longer says “AI Online” before authentication. The check accepts no credentials or endpoint overrides from the browser.

Local verification on 30 October2026 with the user-authorized key and the configured official OpenAI endpoint returned **HTTP401 / invalid_api_key**. The request reached the provider, which rejected the credential. No generated reply is claimed from that key, and no automatic host guessing/fallback was performed. If the credential was issued by a gateway, its confirmed issuing base URL is still required. The key remains in a private ignored local .env, not in this repository.
