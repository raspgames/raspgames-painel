async function getConnectedAccount(machineId) {
  const url =
    `${process.env.SUPABASE_URL}/rest/v1/mercado_accounts` +
    `?machine_id=eq.${encodeURIComponent(machineId)}` +
    `&select=machine_id,access_token` +
    `&limit=1`;

  const res = await fetch(url, {
    method: "GET",
    headers: {
      apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`
    }
  });

  const data = await res.json();

  if (!res.ok) {
    throw new Error(`erro ao buscar conta conectada: ${JSON.stringify(data)}`);
  }

  return data[0] || null;
}

async function updatePaymentStatus(machineId, paymentId, status, rawData) {
  const approvedAt =
    status === "approved" ? new Date().toISOString() : null;

  const url =
    `${process.env.SUPABASE_URL}/rest/v1/payments` +
    `?machine_id=eq.${encodeURIComponent(machineId)}` +
    `&mp_payment_id=eq.${encodeURIComponent(String(paymentId))}`;

  const payload = {
    status: status,
    webhook_payload: rawData
  };

  if (approvedAt) {
    payload.approved_at = approvedAt;
  }

  const res = await fetch(url, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
      Prefer: "return=representation"
    },
    body: JSON.stringify(payload)
  });

  const data = await res.json();

  if (!res.ok) {
    throw new Error(`erro ao atualizar pagamento: ${JSON.stringify(data)}`);
  }

  return data;
}

export async function GET(request) {
  try {
    const { searchParams } = new URL(request.url);
    const machineId = searchParams.get("machine_id");
    const paymentId = searchParams.get("payment_id");

    if (!machineId || !paymentId) {
      return Response.json(
        { error: "machine_id e payment_id são obrigatórios" },
        { status: 400 }
      );
    }

    const account = await getConnectedAccount(machineId);

    if (!account || !account.access_token) {
      return Response.json(
        { error: "máquina sem conta Mercado Pago conectada" },
        { status: 400 }
      );
    }

    const mpRes = await fetch(
      `https://api.mercadopago.com/v1/payments/${encodeURIComponent(paymentId)}`,
      {
        method: "GET",
        headers: {
          Authorization: `Bearer ${account.access_token}`
        }
      }
    );

    const mpData = await mpRes.json();

    if (!mpRes.ok) {
      return Response.json(
        { error: "erro ao consultar status", details: mpData },
        { status: 400 }
      );
    }

    const status = mpData.status || "unknown";

    await updatePaymentStatus(machineId, paymentId, status, mpData);

    return Response.json({
      ok: true,
      machine_id: machineId,
      payment_id: String(paymentId),
      status: status,
      status_detail: mpData.status_detail || null,
      approved: status === "approved",
      transaction_amount: mpData.transaction_amount ?? null
    });
  } catch (error) {
    console.error("payment-status error:", error);

    return Response.json(
      {
        error: "falha no payment-status",
        message: error instanceof Error ? error.message : String(error)
      },
      { status: 500 }
    );
  }
}
