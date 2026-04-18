module.exports = (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  return res.status(200).json({
    ok: true,
    app: "raspgames-servidor",
    status: "online"
  });
};
