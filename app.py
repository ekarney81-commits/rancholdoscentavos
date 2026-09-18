import os
import html
import requests
from flask import Flask, request, jsonify, send_file

app = Flask(__name__)

@app.get("/")
def home():
    return send_file("index.html")

@app.get("/api/send")
def api_status():
    return jsonify({"status": "Mail API is running"})

@app.post("/api/send")
def send_email():
    try:
        data = request.get_json(force=True)

        sender = data.get("from", "").strip()
        recipients = data.get("to", [])
        reply_to = data.get("reply_to", "").strip()
        subject = data.get("subject", "").strip()
        email_body = data.get("body", "")

        if isinstance(recipients, str):
            recipients = [x.strip() for x in recipients.splitlines() if x.strip()]

        api_token = os.environ.get("CLOUDFLARE_API_TOKEN")
        account_id = os.environ.get("CLOUDFLARE_ACCOUNT_ID")

        if not api_token:
            return jsonify({"error": "CLOUDFLARE_API_TOKEN is not configured."}), 500

        if not account_id:
            return jsonify({"error": "CLOUDFLARE_ACCOUNT_ID is not configured."}), 500

        if not sender:
            return jsonify({"error": "Send From is required."}), 400

        if not recipients:
            return jsonify({"error": "At least one recipient is required."}), 400

        if not subject:
            return jsonify({"error": "Subject is required."}), 400

        cloudflare_url = (
            "https://api.cloudflare.com/client/v4/accounts/"
            f"{account_id}/email/sending/send"
        )

        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }

        payload = {
            "from": {"address": sender, "name": "Ashley Mok"},
            "to": recipients,
            "subject": subject,
            "text": email_body,
            "html": "<p>" + html.escape(email_body).replace("\n", "<br>") + "</p>",
        }


        if reply_to:
            payload["reply_to"] = reply_to

        response = requests.post(
            cloudflare_url,
            headers=headers,
            json=payload,
            timeout=30,
        )

        try:
            response_data = response.json()
        except Exception:
            response_data = {}

        if response.ok and response_data.get("success") is True:
            result = response_data.get("result", {})

            delivered = result.get("delivered", [])
            queued = result.get("queued", [])
            failed = result.get("permanent_bounces", [])

            results = []

            for email in delivered:
                results.append({"email": email, "status": "Sent"})

            for email in queued:
                results.append({"email": email, "status": "Sent"})

            for email in failed:
                results.append({"email": email, "status": "Failed"})

            return jsonify({
                "success": True,
                "results": results,
                "sent": len(delivered) + len(queued),
                "queued": len(queued),
                "failed": len(failed),
                "total": len(recipients),
                "message_id": result.get("message_id"),
            })

        return jsonify({
            "success": False,
            "error": response_data.get("errors", response.text),
        }), response.status_code

    except Exception as exc:
        return jsonify({
            "success": False,
            "error": str(exc),
        }), 500
