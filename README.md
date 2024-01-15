# Authz

![build status](https://github.com/CHESSComputing/Authz/actions/workflows/go.yml/badge.svg)
[![go report card](https://goreportcard.com/badge/github.com/CHESSComputing/Authz)](https://goreportcard.com/report/github.com/CHESSComputing/Authz)
[![godoc](https://godoc.org/github.com/CHESSComputing/Authz?status.svg)](https://godoc.org/github.com/CHESSComputing/Authz)

CHESS Authentication/authorization service

### Example
```
# obtain kerberos ticket and put it into JSON

cat record.json
{
    "user": <your-user-name>,
    "ticket": <your kerberos ticket>,
    "scope": <read|write>
}

# create JSON payload
curl -X POST -H "Content-type: application/json" \
    -d./record.json http://localhost:8380/oath/authorize
```
