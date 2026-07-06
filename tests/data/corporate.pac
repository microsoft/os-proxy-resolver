// Typical corporate PAC exercising the common builtins. Deliberately avoids
// unconditional dnsResolve()/isInNet(hostname) so the corpus runs without
// network access (isInNet only sees IP literals here).
function FindProxyForURL(url, host) {
  if (isPlainHostName(host) || dnsDomainIs(host, ".corp.example.com"))
    return "DIRECT";
  if (shExpMatch(host, "[0-9]*.[0-9]*.[0-9]*.[0-9]*") && isInNet(host, "10.0.0.0", "255.0.0.0"))
    return "DIRECT";
  if (shExpMatch(host, "*.blocked.example"))
    return "PROXY blackhole.corp.example.com:9";
  if (url.substring(0, 6) == "https:")
    return "PROXY secure.corp.example.com:8443; DIRECT";
  return "PROXY proxy.corp.example.com:3128; PROXY backup.corp.example.com:3128; DIRECT";
}
