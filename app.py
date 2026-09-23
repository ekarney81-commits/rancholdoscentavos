import re
import os
from pathlib import Path
import time
import html
import requests
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from supabase import create_client
from functools import wraps
from flask import Flask, request, jsonify, send_file, session

load_dotenv(Path(__file__).resolve().parent / '.env.local', override=True)

app = Flask(__name__)
app.secret_key = os.environ.get("MAIL_SESSION_SECRET")
if not app.secret_key:
    raise RuntimeError("MAIL_SESSION_SECRET is not configured.")

ACCESS_CODE = os.environ.get("MAIL_ACCESS_CODE")
if not ACCESS_CODE:
    raise RuntimeError("MAIL_ACCESS_CODE is not configured.")


def require_access(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("mail_access"):
            return jsonify({"success": False, "error": "Access restricted."}), 401
        return fn(*args, **kwargs)
    return wrapped


@app.post("/api/auth/unlock")
def unlock():
    data = request.get_json(silent=True) or {}
    code = str(data.get("code", ""))
    if not code or code != ACCESS_CODE:
        return jsonify({"success": False, "error": "Invalid access code."}), 401
    session["mail_access"] = True
    return jsonify({"success": True})


@app.post("/api/auth/lock")
def lock():
    session.clear()
    return jsonify({"success": True})




@app.get("/")
def home():
    return send_file("index.html")


@app.get("/api/send")
def api_status():
    return jsonify({"status": "Mail API is running"})




def get_encryption_key():
    key = os.environ.get("SENDER_CONFIG_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError(
            "SENDER_CONFIG_ENCRYPTION_KEY is not configured."
        )
    return key.encode()


def get_supabase():
    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")

    if not url or not key:
        raise RuntimeError(
            "Supabase environment variables are not configured."
        )

    return create_client(url, key)


def encrypt_credential(value):
    cipher = Fernet(get_encryption_key())
    return cipher.encrypt(value.encode()).decode()


def decrypt_credential(value):
    cipher = Fernet(get_encryption_key())
    return cipher.decrypt(value.encode()).decode()


def public_sender(row):
    return {
        "id": row["id"],
        "name": row["name"],
        "email": row["email"],
        "provider": row["provider"],
        "reply_to": row.get("reply_to") or row["email"],
        "status": row["status"],
    }



def public_proxy(row, proxy_number=None):
    return {
        "id": row["id"],
        "host": row["host"],
        "port": row["port"],
        "username": row.get("username") or "",
        "status": row.get("status") or "dead",
        "last_checked_at": row.get("last_checked_at"),
        "last_error": row.get("last_error"),
        "proxy_number": proxy_number,
    }


def get_proxy_rows():
    db = get_supabase()
    response = (
        db.table("proxies")
        .select("*")
        .order("created_at")
        .execute()
    )
    return response.data or []


def proxy_url(row):
    host = str(row["host"]).strip()
    port = str(row["port"]).strip()
    username = str(row.get("username") or "")
    password = decrypt_credential(row["password"]) if row.get("password") else ""
    auth = ""
    if username:
        auth = (
            f"{requests.utils.quote(username, safe='')}:"
            f"{requests.utils.quote(password, safe='')}@"
        )
    return f"http://{auth}{host}:{port}"


def test_proxy_row(row):
    proxy = proxy_url(row)
    proxies = {"http": proxy, "https": proxy}
    try:
        response = requests.get(
            "https://www.cloudflare.com/cdn-cgi/trace",
            proxies=proxies,
            timeout=15,
        )
        if not response.ok:
            raise RuntimeError(f"Proxy test returned HTTP {response.status_code}.")
        return True, None
    except Exception as exc:
        return False, str(exc)


def mark_proxy_state(proxy_id, status, error=None):
    db = get_supabase()
    update = {
        "status": status,
        "last_checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "last_error": error,
    }
    db.table("proxies").update(update).eq("id", proxy_id).execute()


def choose_proxy():
    rows = [
        row for row in get_proxy_rows()
        if (row.get("status") or "dead").lower() == "active"
    ]
    if not rows:
        return None

    rows.sort(
        key=lambda row: row.get("last_used_at") or "1970-01-01T00:00:00+00:00"
    )
    selected = rows[0]

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    get_supabase().table("proxies").update(
        {"last_used_at": now}
    ).eq("id", selected["id"]).execute()

    all_rows = get_proxy_rows()
    number_map = {row["id"]: index + 1 for index, row in enumerate(all_rows)}
    selected["proxy_number"] = number_map.get(selected["id"])
    return selected


@app.get("/api/proxies")
@require_access
def get_proxies():
    try:
        rows = get_proxy_rows()
        return jsonify({
            "success": True,
            "proxies": [
                public_proxy(row, index + 1)
                for index, row in enumerate(rows)
            ],
        })
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@app.post("/api/proxies")
@require_access
def add_proxy():
    try:
        data = request.get_json(silent=True) or {}
        host = str(data.get("host", "")).strip()
        port = str(data.get("port", "")).strip()
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", "")).strip()

        if not host or not port or not password:
            return jsonify({
                "success": False,
                "error": "Host, port and password are required.",
            }), 400

        if not port.isdigit() or not 1 <= int(port) <= 65535:
            return jsonify({
                "success": False,
                "error": "Invalid proxy port.",
            }), 400

        row = {
            "host": host,
            "port": int(port),
            "username": username,
            "password": encrypt_credential(password),
            "status": "dead",
            "last_error": None,
        }

        ok, error = test_proxy_row(row)
        row["status"] = "active" if ok else "dead"
        row["last_checked_at"] = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
        )
        row["last_error"] = error

        response = get_supabase().table("proxies").insert(row).execute()
        if not response.data:
            return jsonify({
                "success": False,
                "error": "Failed to save proxy.",
            }), 500

        saved = response.data[0]
        return jsonify({
            "success": ok,
            "proxy": public_proxy(saved),
            "error": error,
        }), 201 if ok else 422

    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@app.patch("/api/proxies/<proxy_id>")
@require_access
def update_proxy(proxy_id):
    try:
        data = request.get_json(silent=True) or {}
        db = get_supabase()

        existing_response = (
            db.table("proxies")
            .select("*")
            .eq("id", proxy_id)
            .limit(1)
            .execute()
        )

        if not existing_response.data:
            return jsonify({
                "success": False,
                "error": "Proxy not found.",
            }), 404

        existing = existing_response.data[0]

        host = str(data.get("host", existing["host"])).strip()
        port = str(data.get("port", existing["port"])).strip()
        username = str(
            data.get("username", existing.get("username") or "")
        ).strip()
        password = str(data.get("password", "")).strip()

        if (
            not host
            or not port
            or not port.isdigit()
            or not 1 <= int(port) <= 65535
        ):
            return jsonify({
                "success": False,
                "error": "Invalid proxy host or port.",
            }), 400

        password_plain = (
            password or decrypt_credential(existing["password"])
        )

        candidate = {
            **existing,
            "host": host,
            "port": int(port),
            "username": username,
            "password": encrypt_credential(password_plain),
        }

        ok, error = test_proxy_row(candidate)

        update = {
            "host": host,
            "port": int(port),
            "username": username,
            "password": candidate["password"],
            "status": "active" if ok else "dead",
            "last_checked_at": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
            ),
            "last_error": error,
        }

        response = (
            db.table("proxies")
            .update(update)
            .eq("id", proxy_id)
            .execute()
        )

        if not response.data:
            return jsonify({
                "success": False,
                "error": "Failed to update proxy.",
            }), 500

        return jsonify({
            "success": ok,
            "proxy": public_proxy(response.data[0]),
            "error": error,
        }), 200 if ok else 422

    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@app.delete("/api/proxies/<proxy_id>")
@require_access
def delete_proxy(proxy_id):
    try:
        get_supabase().table("proxies").delete().eq("id", proxy_id).execute()
        return jsonify({"success": True})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@app.post("/api/proxies/<proxy_id>/test")
@require_access
def test_saved_proxy(proxy_id):
    try:
        db = get_supabase()
        response = (
            db.table("proxies")
            .select("*")
            .eq("id", proxy_id)
            .limit(1)
            .execute()
        )

        if not response.data:
            return jsonify({
                "success": False,
                "error": "Proxy not found.",
            }), 404

        row = response.data[0]
        ok, error = test_proxy_row(row)

        mark_proxy_state(
            proxy_id,
            "active" if ok else "dead",
            error,
        )

        return jsonify({
            "success": ok,
            "error": error,
            "status": "active" if ok else "dead",
        })

    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@app.post("/api/proxies/test-connection")
@require_access
def test_new_proxy():
    try:
        data = request.get_json(silent=True) or {}

        host = str(data.get("host", "")).strip()
        port = str(data.get("port", "")).strip()
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", "")).strip()

        if (
            not host
            or not port
            or not port.isdigit()
            or not password
            or not 1 <= int(port) <= 65535
        ):
            return jsonify({
                "success": False,
                "error": "Host, valid port and password are required.",
            }), 400

        row = {
            "host": host,
            "port": int(port),
            "username": username,
            "password": encrypt_credential(password),
        }

        ok, error = test_proxy_row(row)

        return jsonify({
            "success": ok,
            "error": error,
        })

    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


def get_sender_store():
    db = get_supabase()

    response = (
        db.table("senders")
        .select("*")
        .order("created_at")
        .execute()
    )

    store = {}

    for row in response.data or []:
        store[row["id"]] = {
            "id": row["id"],
            "name": row["name"],
            "email": row["email"],
            "provider": row["provider"],
            "credential": decrypt_credential(row["credential"]),
            "account_id": row.get("account_id"),
            "reply_to": row.get("reply_to") or row["email"],
            "status": row["status"],
        }

    return store


def mark_sender_dead(sender_id):
    if not sender_id:
        return

    try:
        db = get_supabase()

        (
            db.table("senders")
            .update({"status": "dead"})
            .eq("id", sender_id)
            .execute()
        )
    except Exception:
        pass


@app.get("/api/senders")
@require_access
def get_senders():
    try:
        db = get_supabase()

        response = (
            db.table("senders")
            .select("id,name,email,provider,reply_to,status")
            .order("created_at")
            .execute()
        )

        response_json = jsonify({
            "success": True,
            "senders": [
                public_sender(row)
                for row in (response.data or [])
            ]
        })
        response_json.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response_json.headers["Pragma"] = "no-cache"
        return response_json

    except Exception as exc:
        return jsonify({
            "success": False,
            "error": str(exc)
        }), 500


@app.post("/api/senders")
@require_access
def add_sender():
    try:
        data = request.get_json(silent=True) or {}

        name = str(data.get("name", "")).strip()
        email = str(data.get("email", "")).strip()
        reply_to = str(data.get("reply_to", "")).strip() or email
        provider = str(data.get("provider", "")).strip().lower()
        credential = str(data.get("credential", "")).strip()
        account_id = str(data.get("account_id", "")).strip() or None

        if not name or not email or not credential:
            return jsonify({
                "success": False,
                "error": "Name, email and credential are required."
            }), 400

        if not re.match(
            r"^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$",
            email
        ):
            return jsonify({
                "success": False,
                "error": "Invalid sender email address."
            }), 400

        if not re.match(
            r"^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$",
            reply_to
        ):
            return jsonify({
                "success": False,
                "error": "Invalid Reply-To email address."
            }), 400

        if provider not in ("cloudflare", "resend"):
            return jsonify({
                "success": False,
                "error": "Unsupported sender provider."
            }), 400

        if provider == "cloudflare" and not account_id:
            return jsonify({
                "success": False,
                "error": "Cloudflare account ID is required."
            }), 400

        db = get_supabase()

        row = {
            "name": name,
            "email": email,
            "reply_to": reply_to,
            "provider": provider,
            "credential": encrypt_credential(credential),
            "account_id": account_id,
            "status": "active",
        }

        response = (
            db.table("senders")
            .insert(row)
            .execute()
        )

        if not response.data:
            return jsonify({
                "success": False,
                "error": "Failed to save sender."
            }), 500

        return jsonify({
            "success": True,
            "sender": public_sender(response.data[0])
        }), 201

    except Exception as exc:
        return jsonify({
            "success": False,
            "error": str(exc)
        }), 500


@app.delete("/api/senders/<sender_id>")
@require_access
def remove_sender(sender_id):
    try:
        db = get_supabase()

        (
            db.table("senders")
            .delete()
            .eq("id", sender_id)
            .execute()
        )

        return jsonify({
            "success": True
        })

    except Exception as exc:
        return jsonify({
            "success": False,
            "error": str(exc)
        }), 500


@app.post("/api/send")
@require_access
def send_email():
    try:
        data = request.get_json(force=True)

        sender = data.get("sender") or {}
        recipients = data.get("to", [])
        variants = data.get("variants", [])

        if isinstance(recipients, str):
            recipients = [
                x.strip()
                for x in recipients.splitlines()
                if x.strip()
            ]

        if not isinstance(sender, dict):
            return jsonify({
                "error": "A valid sender is required."
            }), 400

        cleaned_variants = []

        for variant in variants:
            if not isinstance(variant, dict):
                continue

            subject = str(variant.get("subject", "")).strip()
            body = str(variant.get("body", "")).strip()

            if subject and body:
                cleaned_variants.append({
                    "subject": subject,
                    "body": body
                })

        if not cleaned_variants:
            return jsonify({
                "error": "At least one complete subject/body variant is required."
            }), 400

        sender_id = str(sender.get("id", "")).strip()

        if not sender_id:
            return jsonify({
                "error": "Sender ID is required."
            }), 400

        # Sender identity and credentials are resolved exclusively
        # from the server-side Supabase store. Never trust the
        # provider, email, name, or credential supplied by the browser.
        sender_store = get_sender_store()
        stored_sender = sender_store.get(sender_id)

        if not stored_sender:
            return jsonify({
                "error": "Sender was not found."
            }), 404

        if stored_sender.get("status") == "dead":
            return jsonify({
                "error": "This sender is marked DEAD and cannot be used.",
                "sender_failed": True,
                "sender_id": sender_id
            }), 409

        sender_name = str(
            stored_sender.get("name", "")
        ).strip()

        sender_address = str(
            stored_sender.get("email", "")
        ).strip()

        sender_reply_to = str(
            stored_sender.get("reply_to", "")
        ).strip() or sender_address

        provider = str(
            stored_sender.get("provider", "")
        ).strip().lower()

        sender_credential = stored_sender.get("credential")
        sender_account_id = stored_sender.get("account_id")

        if not sender_address:
            return jsonify({
                "error": "Sender email address is not configured.",
                "sender_failed": True,
                "sender_id": sender_id
            }), 500

        if not re.match(
            r"^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$",
            sender_address
        ):
            return jsonify({
                "error": "Invalid sender email address.",
                "sender_failed": True,
                "sender_id": sender_id
            }), 500

        if provider not in ("cloudflare", "resend"):
            return jsonify({
                "error": "Unsupported sender provider.",
                "sender_failed": True,
                "sender_id": sender_id
            }), 500

        if not sender_credential:
            return jsonify({
                "error": "Sender credential is not configured.",
                "sender_failed": True,
                "sender_id": sender_id
            }), 500

        if provider == "cloudflare":
            if not sender_account_id:
                return jsonify({
                    "error": "Cloudflare account ID is not configured.",
                    "sender_failed": True,
                    "sender_id": sender_id
                }), 500

            api_url = (
                "https://api.cloudflare.com/client/v4/accounts/"
                f"{sender_account_id}/email/sending/send"
            )

            headers = {
                "Authorization": f"Bearer {sender_credential}",
                "Content-Type": "application/json",
            }

        else:
            api_url = "https://api.resend.com/emails"

            headers = {
                "Authorization": f"Bearer {sender_credential}",
                "Content-Type": "application/json",
            }

        results = []
        sent = 0
        failed = 0

        import random

        shuffled_variants = []

        while len(shuffled_variants) < len(recipients):
            batch = list(
                range(len(cleaned_variants))
            )
            random.shuffle(batch)
            shuffled_variants.extend(batch)

        for index, recipient in enumerate(recipients):
            variant_index = shuffled_variants[index]
            variant = cleaned_variants[variant_index]

            proxy_row = choose_proxy()
            request_proxies = None
            proxy_number = None

            if proxy_row:
                request_proxies = {
                    "http": proxy_url(proxy_row),
                    "https": proxy_url(proxy_row),
                }
                proxy_number = proxy_row.get("proxy_number")

            if provider == "cloudflare":
                payload = {
                    "from": {
                        "address": sender_address,
                        "name": sender_name
                    },
                    "to": [recipient],
                    "reply_to": sender_reply_to,
                    "subject": variant["subject"],
                    "text": variant["body"],
                    "html": (
                        "<p>"
                        + html.escape(
                            variant["body"]
                        ).replace(
                            "\n",
                            "<br>"
                        )
                        + "</p>"
                    ),
                }

            else:
                from_value = (
                    f"{sender_name} "
                    f"<{sender_address}>"
                    if sender_name
                    else sender_address
                )

                payload = {
                    "from": from_value,
                    "to": [recipient],
                    "reply_to": sender_reply_to,
                    "subject": variant["subject"],
                    "text": variant["body"],
                    "html": (
                        "<p>"
                        + html.escape(
                            variant["body"]
                        ).replace(
                            "\n",
                            "<br>"
                        )
                        + "</p>"
                    ),
                }

            try:
                response = requests.post(
                    api_url,
                    headers=headers,
                    json=payload,
                    proxies=request_proxies,
                    timeout=30,
                )

                try:
                    response_data = response.json()
                except Exception:
                    response_data = {}

                if provider == "cloudflare":
                    provider_success = (
                        response.ok
                        and response_data.get("success") is True
                    )
                else:
                    provider_success = (
                        response.ok
                        and bool(
                            response_data.get("id")
                        )
                    )

                if provider_success:
                    sent += 1

                    if provider == "cloudflare":
                        result_data = (
                            response_data.get(
                                "result",
                                {}
                            )
                        )

                        message_id = (
                            result_data.get(
                                "message_id"
                            )
                        )
                    else:
                        message_id = (
                            response_data.get("id")
                        )

                    results.append({
                        "email": recipient,
                        "status": "Sent",
                        "variant": variant_index + 1,
                        "proxy_number": proxy_number,
                        "message_id": message_id,
                        "sender_id": sender_id,
                        "sender": sender_address,
                        "provider": provider,
                    })

                else:
                    failed += 1

                    error_data = (
                        response_data.get(
                            "errors"
                        )
                        if provider == "cloudflare"
                        else response_data.get(
                            "message"
                        )
                    )

                    if not error_data:
                        error_data = response.text

                    # A provider/authentication/configuration
                    # failure can invalidate the sender.
                    sender_failed = (
                        response.status_code
                        in (401, 403, 422)
                    )

                    results.append({
                        "email": recipient,
                        "status": "Failed",
                        "variant": variant_index + 1,
                        "proxy_number": proxy_number,
                        "error": error_data,
                        "sender_id": sender_id,
                        "sender": sender_address,
                        "provider": provider,
                        "sender_failed": sender_failed,
                    })

                    if sender_failed:
                        mark_sender_dead(sender_id)

                        return jsonify({
                            "success": False,
                            "results": results,
                            "sent": sent,
                            "failed": failed,
                            "total": len(recipients),
                            "sender_failed": True,
                            "sender_id": sender_id,
                            "sender": sender_address,
                            "provider": provider,
                        }), 502

            except requests.RequestException as exc:
                failed += 1

                results.append({
                    "email": recipient,
                    "status": "Failed",
                    "variant": variant_index + 1,
                    "error": str(exc),
                    "sender_id": sender_id,
                    "sender": sender_address,
                    "provider": provider,
                    "sender_failed": False,
                })

            except Exception as exc:
                failed += 1

                results.append({
                    "email": recipient,
                    "status": "Failed",
                    "variant": variant_index + 1,
                    "error": str(exc),
                    "sender_id": sender_id,
                    "sender": sender_address,
                    "provider": provider,
                    "sender_failed": False,
                })

        return jsonify({
            "success": failed == 0,
            "results": results,
            "sent": sent,
            "failed": failed,
            "total": len(recipients),
            "sender_failed": False,
            "sender_id": sender_id,
            "sender": sender_address,
            "provider": provider,
        })

    except Exception as exc:
        return jsonify({
            "success": False,
            "error": str(exc),
        }), 500


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )
