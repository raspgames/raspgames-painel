
function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

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

export default async function handler(req, res) {
  setCors(res);

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Método não permitido" });
  }

  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body) : req.body || {};
    const machineId = String(body.machine_id || "").trim().toUpperCase();
    const ownerUserId = String(body.owner_user_id || "").trim();

    if (!machineId) {
      return res.status(400).json({ error: "machine_id obrigatório" });
    }

    if (!ownerUserId) {
      return res.status(400).json({ error: "owner_user_id obrigatório" });
    }

    const machine = await getMachine(machineId);

    if (!machine) {
      return res.status(404).json({ error: "máquina não encontrada" });
    }

    if (machine.owner_user_id && machine.owner_user_id !== ownerUserId) {
      return res.status(409).json({ error: "essa máquina já está vinculada a outro usuário" });
    }

    if (machine.owner_user_id === ownerUserId) {
      return res.status(200).json({
        ok: true,
        already_linked: true,
        machine
      });
    }

    const updated = await bindMachine(machineId, ownerUserId);

    return res.status(200).json({
      ok: true,
      machine: updated
    });
  } catch (error) {
    return res.status(500).json({
      error: "falha no bind-machine",
      message: error instanceof Error ? error.message : String(error)
    });
  }
}
