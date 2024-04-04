function main() {
  let did = $request.headers["Device-Id"];
  if (!did) {
    $done();
    return;
  }
  let now = parseInt(new Date().getTime() / 1000);
  let exp = now + 7 * 24 * 60 * 60;
  let exp_date = new Date(exp * 1000).toISOString();
  let payload = {
    expiry_date: exp_date,
    iat: now,
    iss: "aptakube-com",
    exp: exp,
  };
  let header = {
    alg: "HS512",
  };
  let b64url_encode = function (str) {
    return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };

  let header_b64 = b64url_encode(JSON.stringify(header));
  let payload_b64 = b64url_encode(JSON.stringify(payload));

  let enc = new TextEncoder("utf-8");
  window.crypto.subtle
    .importKey(
      "raw",
      enc.encode(did),
      {
        name: "HMAC",
        hash: { name: "SHA-512" },
      },
      false,
      ["sign", "verify"]
    )
    .then((key) => {
      window.crypto.subtle
        .sign("HMAC", key, enc.encode(header_b64 + "." + payload_b64))
        .then((signature) => {
          let signature_b64 = b64url_encode(
            String.fromCharCode.apply(null, new Uint8Array(signature))
          );
          let jwt = header_b64 + "." + payload_b64 + "." + signature_b64;
          let body = {
            expiry_date: exp_date,
            token: jwt,
          };
          $done({ body: JSON.stringify(body) });
        });
    });
}

main();
