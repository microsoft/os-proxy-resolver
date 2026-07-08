// Microsoft PAC extensions are enabled in the evaluator (as in WinHTTP and
// Chromium): when FindProxyForURLEx is defined, the engine prefers it over
// FindProxyForURL. This file pins that precedence.
function FindProxyForURL(url, host) {
  return "PROXY plain.example.com:3128";
}

function FindProxyForURLEx(url, host) {
  return "HTTPS tls-proxy.example.com:8443; DIRECT";
}
