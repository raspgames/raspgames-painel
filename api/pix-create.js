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

async function savePayment(payload) {
  const url = `${process.env.SUPABASE_URL}/rest/v1/payments`;

  const res = await fetch(url, {
    method: "POST",
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
    throw new Error(`erro ao salvar pagamento: ${JSON.stringify(data)}`);
  }

  return data;
}

export async function POST(request) {
  try {
    const body = await request.json();

    const machineId = body.machine_id;
    const amount = Number(body.amount);
    const credits = Number(body.credits || 1);

    if (!machineId || !amount || amount <= 0) {
      return Response.json(
        { error: "machine_id e amount válidos são obrigatórios" },
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

    const externalReference = `RG_${machineId}_${Date.now()}`;

    const mpRes = await fetch("https://api.mercadopago.com/v1/payments", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${account.access_token}`
      },
     body: JSON.stringify({
  transaction_amount: amount,
  description: `Crédito fliperama ${machineId}`,
  payment_method_id: "pix",
  external_reference: externalReference,
  notification_url: `${process.env.APP_BASE_URL}/api/webhook`,
  payer: {
    email: "teste@raspgames.com.br"
  }
})
    });

    const mpData = await mpRes.json();

    if (!mpRes.ok) {
      return Response.json(
        { error: "erro ao criar pix", details: mpData },
        { status: 400 }
      );
    }

    const qrText =
      mpData?.point_of_interaction?.transaction_data?.qr_code || null;

    const qrBase64 =
      mpData?.point_of_interaction?.transaction_data?.qr_code_base64 || null;

    await savePayment({
      machine_id: machineId,
      mp_payment_id: String(mpData.id),
      external_reference: externalReference,
      amount: amount,
      credits: credits,
      status: mpData.status || "pending",
      payment_method: "pix",
      qr_text: qrText,
      qr_base64: qrBase64,
      webhook_payload: mpData
    });

    return Response.json({
      ok: true,
      payment_id: String(mpData.id),
      status: mpData.status,
      qr_text: qrText,
      qr_base64: qrBase64
    });
  } catch (error) {
    console.error("pix-create error:", error);

    return Response.json(
      {
        error: "falha no pix-create",
        message: error instanceof Error ? error.message : String(error)
      },
      { status: 500 }
    );
  }
}
