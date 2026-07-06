// Mixed proxy kinds and portless entries.
function FindProxyForURL(url, host) {
  if (host == "always-direct.example") return "DIRECT";
  if (host == "no-port.example") return "PROXY noport; SOCKS nosocks";
  return "SOCKS5 socks.example.com:1080; SOCKS legacy.example.com; DIRECT";
}
