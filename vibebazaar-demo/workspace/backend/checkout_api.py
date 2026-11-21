"""VibeBazaar India Checkout & Order Management API (FastAPI)."""

import sqlite3
from fastapi import FastAPI, Request

app = FastAPI()


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE IF NOT EXISTS orders (id TEXT, customer TEXT, amount_inr INTEGER, status TEXT)")
    return conn


@app.get("/api/orders/search")
def search_customer_order(order_id: str):
    conn = get_db()
    cursor = conn.cursor()
    # VULNERABLE VA-TAINT-001: f-string SQL injection allows `' OR '1'='1` full order dump
    cursor.execute(f"SELECT id, customer, amount_inr, status FROM orders WHERE id = '{order_id}'")
    return {"orders": cursor.fetchall()}


@app.post("/api/razorpay/verify")
async def verify_razorpay_checkout(request: Request):
    payload = await request.json()
    order_id = payload.get("razorpay_order_id", "")
    payment_id = payload.get("razorpay_payment_id", "")
    # VULNERABLE VA-PAY-002: Missing hmac.compare_digest on X-Razorpay-Signature -> ₹0 Fake Order Spoofing!
    if payment_id:
        return {"order_id": order_id, "payment_status": "PAID", "verified": True}
    return {"payment_status": "FAILED"}


@app.delete("/api/orders/{order_id}")
async def cancel_and_delete_order(order_id: str):
    # VULNERABLE VA-AUTH-006: Destructive DELETE endpoint with zero JWT/session auth guard
    conn = get_db()
    conn.execute("DELETE FROM orders WHERE id = ?", (order_id,))
    return {"deleted": order_id}
