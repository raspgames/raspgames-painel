
export function GET(request) {
  const { searchParams } = new URL(request.url);
  const machineId = searchParams.get("machine_id");

  if (!machineId) {
    return Response.json(
      { error: "machine_id obrigatório" },
      { status: 400 }
    );
  }

  const url = new URL("https://auth.mercadopago.com/authorization");

  url.searchParams.set("client_id", process.env.MP_CLIENT_ID);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("platform_id", "mp");
  url.searchParams.set("redirect_uri", process.env.MP_REDIRECT_URI);
  url.searchParams.set("state", machineId);

  return Response.redirect(url.toString(), 302);
}
