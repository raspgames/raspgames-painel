async function getPendingCommand(machineId) {
  const url =
    `${process.env.SUPABASE_URL}/rest/v1/machine_commands` +
    `?machine_id=eq.${encodeURIComponent(machineId)}` +
    `&status=eq.pending` +
    `&order=created_at.asc` +
    `&limit=1`;

  const res = await fetch(url, {
    headers: {
      apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`
    }
  });

  const data = await res.json();
  if (!res.ok) throw new Error(JSON.stringify(data));
  return data[0] || null;
}

async function markExecuted(commandId) {
  const url =
    `${process.env.SUPABASE_URL}/rest/v1/machine_commands` +
    `?id=eq.${encodeURIComponent(String(commandId))}`;

  const res = await fetch(url, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
      Prefer: "return=representation"
    },
    body: JSON.stringify({
      status: "executed",
      executed_at: new Date().toISOString()
    })
  });

  const data = await res.json();
  if (!res.ok) throw new Error(JSON.stringify(data));
  return data;
}

export async function GET(request) {
  try {
    const { searchParams } = new URL(request.url);
    const machineId = String(searchParams.get("machine_id") || "").trim();

    if (!machineId) {
      return Response.json({ error: "machine_id obrigatório" }, { status: 400 });
    }

    const cmd = await getPendingCommand(machineId);

    return Response.json({
      ok: true,
      command: cmd
    });
  } catch (error) {
    return Response.json(
      {
        error: "falha no remote-command GET",
        message: error instanceof Error ? error.message : String(error)
      },
      { status: 500 }
    );
  }
}

export async function POST(request) {
  try {
    const body = await request.json();
    const commandId = body.command_id;

    if (!commandId) {
      return Response.json({ error: "command_id obrigatório" }, { status: 400 });
    }

    const data = await markExecuted(commandId);

    return Response.json({
      ok: true,
      updated: data
    });
  } catch (error) {
    return Response.json(
      {
        error: "falha no remote-command POST",
        message: error instanceof Error ? error.message : String(error)
      },
      { status: 500 }
    );
  }
}
