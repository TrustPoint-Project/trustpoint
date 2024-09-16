### Automatic Onboarding Key Infrastructure (AOKI) v0.1 zero-touch demo

#### Generating new test certs

- Clone `trustpoint-devid-module` repo and install
- Copy generate_toki_test_certs.py to the 'tests' folder and run

#### Instructions for use

- Ensure both trustpoint and client are on the `aoki_zero_touch` branch
- Add IDevID and ownership certificate to Trustpoint as truststores (the certificates themselves, chain validation TBD)
- `cp owner_private.key ../../../trustpoint`
- copy `idevid_cert.pem` and `idevid_private.key` to client (trustpoint-client/trustpoint_client)
- run `trustpoint_client start-zero-touch`