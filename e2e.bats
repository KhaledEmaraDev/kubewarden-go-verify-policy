#!/usr/bin/env bats

@test "reject because name is on deny list" {
  run kwctl run annotated-policy.wasm -r test_data/pod.json --settings-json '{"image": "ghcr.io/khaledemaradev/policies/verify-images@sha256:ccfd054335dbfd8ae33d26cf09dca5754631ab05762c6892b8a98615655203f8", "pub_keys": ["-----BEGIN CERTIFICATE-----\nMIIFPjCCAyagAwIBAgIUP8qULlA3/BN6L63Nt3D2fiYDuCMwDQYJKoZIhvcNAQEL\nBQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMjMwMzMxMDkwNTE1WhcNMjQw\nMzMwMDkwNTE1WjAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCCAiIwDQYJKoZIhvcN\nAQEBBQADggIPADCCAgoCggIBAJdhevmcXezHH2uK1ZmdWsOdqn/wQBhOvBwM5cV4\nH8XY1SrDf/H5s0vT9SW+Dwxf2aGTBaOcmJYjp1qDzK/qs1YcKzJwjL8TFsl474J8\nMGiz2d5tx/dpbgkXRml7Z0XztxFCYQ0V7smvbKYzEQL0ADEV4upZXYQadcB0MBym\nXp3YT2l2tohz9SHLJkdGKn/mkW1KbHUQeLwVw4Vh9i+7OeBd9H2kGzARXe1Wbp+E\ne5akjJUE1AUXYFGtkBe94loFdrbFkm/ori//GODQl1slBv0R0vLEflZ4WOzVxslw\nZt398o4BwJmeUGP6K0ZVAb75M9yC5EufFBwqrnG7+8zaGka43lXuzlquOR2gcJYz\nrZchWIFv2cmFC1P789YWJ3n88+ZwFFnuyCd+RWoNWtpaTEVyu+qNMy4rep/quCS3\nqkfbFZjpg7q4bITLchW+0dRsw4O1bI3QwPziaaf0jmNi1dyKA+ZjmL6CAURjdA0f\nbCATN7NAZs0jIURC/iHiCqWMBMfE6ajX8ySQLM1juc8M1G0lQlKfgWXHYvAhqjxe\nOlWWs//C8fhuh7BYkuaFDayfCXio3/pfyzbfCETe6Ar3bkuqqJzxDXep8cI0xfxk\nD2qCrafVycl91iF26r2yHIk2guAA+Kde+zTWx2lgysPwuBD1SlURvCcS+ILeldD3\n2WDhAgMBAAGjgYMwgYAwHQYDVR0OBBYEFKkaJR1PGXzqS1Q0BXwaNY/Bos1nMB8G\nA1UdIwQYMBaAFKkaJR1PGXzqS1Q0BXwaNY/Bos1nMA8GA1UdEwEB/wQFMAMBAf8w\nLQYDVR0RBCYwJIILZXhhbXBsZS5jb22CD3d3dy5leGFtcGxlLm5ldIcECgAAATAN\nBgkqhkiG9w0BAQsFAAOCAgEAa8Bn+8pz2t3QaLM/FAmJKevy8vf9EZBB0t7ph0XW\nQ154bTdAmxK+7C6y1zuYF3Wf1L4q+iNrXHFc+iXbXqCIfhD6bUOMhHebEOIeDLnN\nV0fAiDEoaUvDdNFuJbrPmjJSksRPP/R2ssuc2TnnOrF5gvL4sNKA5yvYEjCs7Vs3\nLKOcJOf88Y02vchRn0Xu+GJ6uZ28on9t3HllPpI36ZTcVuJVEmJFPb0k3Mp+skiI\npmL8juNZC+oEJ9Gd7jnOkUZodo1tdes7Mf14nh6MGYYIpGEM8THoEY5d9zFDcJT3\nMnlrRg/vJ8/3OvJRT/0iNGVmAva3UNEnOMmbfoki9oS/hMe8KKQKBYboegjjuKjP\n8+Y36cfmkvvQsZDAX2l7eUB8HKD2Nzi2p0rJYnEXxRpK2ff6nKMczieg/k/YiU6n\n+4pdZeXkeEPZk+0+M44tuBgR9ciNi4IfHIxgTARkr132LQNaIZm3DvZmlSLY5b1v\nHKJJ4ERuuDP98VUmuSwbFaL6zk4RRCDS1FWBXq2g1Y6wM7ebJwQbDXJcEhc2+G0e\nvfpdTQiv7SXg8YkZ71I1+tcyk9Y5IMwnTjL6JsVQLNWogeoVXRltrUBPxPFsHYde\n7jwqULfYFSBvW4Hhk6tn+TvEgmhCAoP4tDdhEZ4nMJeSASCkm+ViGdyy6cmjPjRE\nVos=\n-----END CERTIFICATE-----\n"]}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request rejected
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}
