## Generate root certificate
```bash
openssl req -x509 -newkey rsa:4096 -keyout privkey -out cert -days 365 -nodes -subj "/CN=Quicer Co Root CA/O=Quicer Co/C=US"
```