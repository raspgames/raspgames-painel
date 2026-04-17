async function updateMachinePing(machineId) {
  const url =
    `${process.env.SUPABASE_URL}/rest/v1/machines` +
    `?machine_id=eq.${encodeURIComponent(machineId)}`;

  const payload = {
    status: "online",
    ultimo_ping: new Date().toISOString()
  };

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
    throw new Error(`erro ao atualizar ping: ${JSON.stringify(data)}`);
  }

  return data;
}

export async function POST(request) {
  try {
    const body = await request.json();
    const machineId = body.machine_id;

    if (!machineId) {
      return Response.json(
        { error: "machine_id é obrigatório" },
        { status: 400 }
      );
    }

    const data = await updateMachinePing(machineId);

    return Response.json({
      ok: true,
      machine_id: machineId,
      updated: data
    });
  } catch (error) {
    console.error("machine-ping error:", error);

    return Response.json(
      {
        error: "falha no machine-ping",
        message: error instanceof Error ? error.message : String(error)
      },
      { status: 500 }
    );
  }
}
