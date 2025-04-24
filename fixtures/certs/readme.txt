1. api.acme.com.crt 和 api.acme.com.key 用在 api server
2. wildcard.acme.com.crt 和 wildcard.acme.com.key 用在 web server
3. 他们都是用 ca.csr 生成的，相当与是 ca 签发给它们，ca.crt 和 ca.key 用在 proxy server 上
