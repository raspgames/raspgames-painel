
export function GET() {
  return Response.json({
    ok: true,
    app: "raspgames-servidor",
    status: "online"
  });
}
