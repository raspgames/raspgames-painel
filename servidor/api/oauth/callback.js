
async function supabaseUpsert(table, body) {
  const url = `${process.env.SUPABASE_URL}/rest/v1/${table}?on_conflict=machine_id`;

  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
      Prefer: "resolution=merge-duplicates,return=representation"
    },
    body: JSON.stringify(body)
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Supabase ${table}: ${text}`);
  }

  return res.json();
}

export async function GET(request) {
  try {
    const { searchParams } = new URL(request.url);
    const code = searchParams.get("code");
    const machineId = searchParams.get("state");

    if (!code || !machineId) {
      return Response.json(
        { error: "code ou state ausente" },
        { status: 400 }
      );
    }

    const tokenRes = await fetch("https://api.mercadopago.com/oauth/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        client_id: process.env.MP_CLIENT_ID,
        client_secret: process.env.MP_CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: process.env.MP_REDIRECT_URI
      })
    });

    const tokenJson = await tokenRes.json();

    if (!tokenRes.ok) {
      return Response.json(
        { error: "erro ao trocar code por token", details: tokenJson },
        { status: 400 }
      );
    }

    const expiresAt = tokenJson.expires_in
      ? new Date(Date.now() + tokenJson.expires_in * 1000).toISOString()
      : null;

    await supabaseUpsert("machines", {
      machine_id: machineId,
      connected: true
    });

    await supabaseUpsert("mercado_accounts", {
      machine_id: machineId,
      mp_user_id: String(tokenJson.user_id || ""),
      access_token: tokenJson.access_token,
      refresh_token: tokenJson.refresh_token || null,
      expires_at: expiresAt
    });

    return new Response(
      `
      <html>
        <body style="font-family: Arial; padding: 24px;">
          <h2>Conta conectada com sucesso</h2>
          <p>Máquina: <strong>${machineId}</strong></p>
          <p>Pode voltar para a máquina.</p>
        </body>
      </html>
      `,
      {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      }
    );
  } catch (error) {
    return Response.json(
      {
        error: "falha no callback",
        message: error.message
      },
      { status: 500 }
    );
  }
}

