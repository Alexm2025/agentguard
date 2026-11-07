# Launch checklist

How to put a public, sign-up-enabled AgentGuard online with Render. It takes about 20 minutes.

## 1. Publish the classifier weights (once)

The Docker build downloads the ML classifier from this repository's releases and checks its SHA-256. From a
machine that has the trained model in `ml/artifacts/injection-classifier-v1`:

```bash
mkdir -p dist/injection-classifier-v1
cp ml/artifacts/injection-classifier-v1/{model.onnx,tokenizer.json,agentguard.json} dist/injection-classifier-v1/
cp ml/reports/injection-classifier-v1.md dist/injection-classifier-v1/MODEL_CARD.md
cp ml/datasets.yaml dist/injection-classifier-v1/DATA_SOURCES.yaml
tar -C dist -czf dist/injection-classifier-v1.tar.gz injection-classifier-v1
sha256sum dist/injection-classifier-v1.tar.gz
gh release create model-injection-classifier-v1 dist/injection-classifier-v1.tar.gz \
  --title "Injection classifier v1 (model weights)" --notes "Weights for the on-device prompt-injection classifier."
```

If the printed checksum differs from `MODEL_SHA256` in `render.yaml`, update `render.yaml` to match. Skip this step
and remove `MODEL_URL` from `render.yaml` to launch without the classifier (taint tracking and heuristics only).

## 2. Set up an email provider

Needed for email verification and password reset. Any SMTP provider works (for example Resend, Brevo, Postmark,
Amazon SES or Mailgun). Verify your sending domain with the provider, then note:

- `AGENTGUARD_SMTP_URL`: `smtp://USER:PASSWORD@HOST:587` (STARTTLS) or `smtps://USER:PASSWORD@HOST:465`
- `AGENTGUARD_MAIL_FROM`: for example `AgentGuard <no-reply@yourdomain.com>`

!!! warning "On Render's free plan, use port 2525"
    Render's free web services block outbound email on ports 25, 465 and 587. Most providers also accept
    port **2525** (Brevo, Mailgun, SendGrid, Postmark; Resend uses 2587 or `smtps` on 2465), for example
    `smtp://USER:PASSWORD@smtp-relay.brevo.com:2525`. If the confirmation email can't be sent, sign-up shows an
    error and saves nothing, so people can retry once email works.

You can also launch without email: sign-up then works without a confirmation step, and password reset is
unavailable until you add it.

## 3. Deploy on Render

1. Open **https://render.com/deploy?repo=https://github.com/Alexm2025/agentguard** and sign in.
2. Choose plans. Free plans are fine to start, with these limits:

    - The web service **sleeps after 15 minutes without visitors**; the next visit takes about a minute to wake it.
      Agents that call it during that minute wait or, with the default fail-closed setting, have risky actions
      stopped.
    - The free database **expires 30 days after it is created** (Render emails you before). Upgrade it before then
      or everyone's accounts and activity are lost.
    - 512 MB of memory: enough (AgentGuard with the classifier uses about 160 MB).
    - Outbound email ports are blocked (see step 2).
3. Fill in the values Render asks for:

    | Setting | Value |
    |---|---|
    | `AGENTGUARD_SMTP_URL`, `AGENTGUARD_MAIL_FROM` | from step 2 |
    | `AGENTGUARD_OPERATOR_NAME` | your name or company, shown on the Terms and Privacy pages |
    | `AGENTGUARD_CONTACT_EMAIL` | where users can reach you about their account and data |
    | `AGENTGUARD_BOOTSTRAP_ADMIN_EMAIL`, `..._PASSWORD` | optional: your own admin account |

4. Click **Apply**. The first build takes a few minutes. Database tables are created automatically.

## 4. Check it

- Open the `onrender.com` address Render shows. The landing page should load over HTTPS.
- `/readyz` returns `{"status": "ready"}`.
- Sign up with a real email address; the verification email should arrive.
- On **Home**, click **Show me an example**. On an event, open **Technical details**: a detector row named **ML**
  means the classifier was installed.
- Read `/terms` and `/privacy` and check your name and contact email are shown.

## 5. Before you announce it

- **Have the Terms of service and Privacy policy reviewed** for your country and business. The built-in pages are a
  starting point that describes what the software actually does; they are not legal advice.
- **Use your own domain** (Render → Settings → Custom domains) and set `AGENTGUARD_PUBLIC_URL` to it.
- **Back up the database**: paid Render databases include daily backups; check they are on.
- **Watch the logs** for the first days (Render → Logs).
- Activity is deleted automatically after 90 days (`AGENTGUARD_EVENT_RETENTION_DAYS`). If a user asks you to delete
  their account, remove their user and workspace from the database.
