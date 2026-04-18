const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization"
};

async function getMachine(machineId) {
  const url =
    `${process.env.SUPABASE_URL}/rest/v1/machines` +
    `?machine_id=eq.${encodeURIComponent(machineId)}` +
    `&select=id,machine_id,owner_user_id`;

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

async function bindMachine(machineId, ownerUserId) {
  const url =
    `${process.env.SUPABASE_URL}/rest/v1/machines` +
    `?machine_id=eq.${encodeURIComponent(machineId)}`;

  const res = await fetch(url, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
      Prefer: "return=representation"
    },
    body: JSON.stringify({
      owner_user_id: ownerUserId
    })
  });

  const data = await res.json();
  if (!res.ok) throw new Error(JSON.stringify(data));
  return data[0] || null;
}

export async function OPTIONS() {
  return new Response(null, {
    status: 204,
    headers: corsHeaders
  });
}

export async function POST(request) {
  try {
    const body = await request.json();
    const machineId = String(body.machine_id || "").trim();
    const ownerUserId = String(body.owner_user_id || "").trim();

    if (!machineId) {
      return Response.json(
        { error: "machine_id obrigatório" },
        { status: 400, headers: corsHeaders }
      );
    }

    if (!ownerUserId) {
      return Response.json(
        { error: "owner_user_id obrigatório" },
        { status: 400, headers: corsHeaders }
      );
    }

    const machine = await getMachine(machineId);

    if (!machine) {
      return Response.json(
        { error: "máquina não encontrada" },
        { status: 404, headers: corsHeaders }
      );
    }

    if (machine.owner_user_id && machine.owner_user_id !== ownerUserId) {
      return Response.json(
        { error: "essa máquina já está vinculada a outro usuário" },
        { status: 409, headers: corsHeaders }
      );
    }

    if (machine.owner_user_id === ownerUserId) {
      return Response.json(
        { ok: true, already_linked: true, machine },
        { headers: corsHeaders }
      );
    }

    const updated = await bindMachine(machineId, ownerUserId);

    return Response.json(
      { ok: true, machine: updated },
      { headers: corsHeaders }
    );
  } catch (error) {
    return Response.json(
      {
        error: "falha no bind-machine",
        message: error instanceof Error ? error.message : String(error)
      },
      { status: 500, headers: corsHeaders }
    );
  }
}
