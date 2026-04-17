export async function GET(request) {
  try {
    const { searchParams } = new URL(request.url);
    const machineId = searchParams.get("machine_id");

    if (!machineId) {
      return Response.json(
        { error: "machine_id obrigatório" },
        { status: 400 }
      );
    }

    const url = `${process.env.SUPABASE_URL}/rest/v1/machines?machine_id=eq.${encodeURIComponent(machineId)}&select=machine_id,connected`;

    const res = await fetch(url, {
      headers: {
        apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`
      }
    });

    const data = await res.json();

    if (!res.ok) {
      return Response.json(
        { error: "erro ao consultar máquina", details: data },
        { status: 500 }
      );
    }

    return Response.json({
      ok: true,
      machine: data[0] || null
    });
  } catch (error) {
    return Response.json(
      { error: "falha no machine-status", message: error.message },
      { status: 500 }
    );
  }
}
