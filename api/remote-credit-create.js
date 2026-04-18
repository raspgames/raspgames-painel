const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization"
};

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
    const credits = Number(body.credits || 1);

    if (!machineId) {
      return Response.json(
        { error: "machine_id obrigatório" },
        { status: 400, headers: corsHeaders }
      );
    }

    const payload = {
      machine_id: machineId,
      command: "send_credit",
      credits: credits > 0 ? credits : 1,
      status: "pending"
    };

    const res = await fetch(`${process.env.SUPABASE_URL}/rest/v1/machine_commands`, {
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
      return Response.json(
        { error: "erro ao criar comando", details: data },
        { status: 500, headers: corsHeaders }
      );
    }

    return Response.json(
      {
        ok: true,
        command: data?.[0] || null
      },
      { headers: corsHeaders }
    );
  } catch (error) {
    return Response.json(
      {
        error: "falha no remote-credit-create",
        message: error instanceof Error ? error.message : String(error)
      },
      { status: 500, headers: corsHeaders }
    );
  }
}
