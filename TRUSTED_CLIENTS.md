# Trusted Client support

The **CHESS/Authz** service (part of the `github.com/CHESSComputing/Authz`
repository) provides authentication and authorization capabilities. Trusted
clients can obtain OAuth tokens by submitting encrypted device-binding payloads
to the dedicated `/oauth/trusted` endpoint.

---

## Payload Structure

To communicate with `/oauth/trusted` end-point user must provide the following
encrypted payload. It represents user identification and device fingerprinting data:

```json
{
  "user": "username",
  "ip_address": ["192.168.1.100", "10.0.0.5"],
  "mac_address": [{"name": "node1", "address": "aa:bb:xx:yy:zz"}, ...]
}
```

### Step-by-Step Flow

1. ssh to the trusted node and obtain its IP and mac addresses

2. Encrypt the Payload
Use the [enc](https://github.com/CHESSComputing/gotools/tree/main/enc) utility from gotools:

```
# write encrypted content to provide file
enc -cipher aes -entry '{"user":"joe", "ip_addresses":["192.168.1.100"], "mac_addresses":[{"name": "node1", "address": "aa:bb:xx:yy:zz"}]}' -secret bla -action encrypt -fout /tmp/file.bin
```

3. Send to /oauth/trusted Endpoint

```
curl -X POST \
    -H "Content-Type: application/octet-stream" \
    --data-binary @/tmp/file.bin \
    http://foxden-authz.url/oauth/trusted
```


4. Receive Token Response

```
Expected response:{
  "access_token": "<jwt-token>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

### Error Handling

| HTTP Status | Meaning |
|-------------|---------|
| 200 | Token issued successfully |
| 400 | Invalid payload or decryption failure |
| 401 | User not authorized or credentials invalid | 
| 403 | Trusted client not registered |
| 500 | Internal server error |


Complete example using `foxden` CLI

```
# request a token with read and write scope
FOXDEN_TRUSTED_CLIENT=1 foxden token create read+write

# view token assigned to variable t
foxden token view --token=$t

AccessToken  :  eyJh...
Issuer       :  CHESS Authz server
User         :  abc
Token Scope  :  read+write
Kind         :  trusted_client
Groups       :  []
Scopes       :  []
ExpiresAt    :  2026-08-25 11:45:21 -0400 EDT
```

### Security Notes

- Encryption Key Management: Store encryption keys securely (not in code)
- HTTPS Only: Always use TLS for communication with the Authz server
- Device Binding: The ip_address and mac_address fields enable device fingerprinting—ensure they accurately represent authorized clients
- Token Expiration: Monitor `expires_in` and implement token refresh logic
