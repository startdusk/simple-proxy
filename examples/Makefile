# curl 可以发送http2请求，restclient 不行

# CURL是一个用于发送和接收HTTP请求的命令行工具。在Linux系统中，可以使用CURL命令来访问使用SSL / TLS进行加密的网站，正常情况下会验证服务器的证书。下面是关于如何使用CURL命令进行证书访问的一些重要的要点：

# 1. 跳过SSL证书验证：如果你需要在访问某个网站时跳过SSL证书验证，可以使用-CURL的”-k”选项。例如，以下命令将跳过证书验证并访问带有自签名证书的网站：

# “`
# curl -k https://example.com
# “`

# 2. 指定CA证书文件：如果你有一个CA证书文件，你可以通过在CURL命令中使用”–cacert”选项来指定该文件的路径。例如，以下命令将使用CA证书文件来验证服务器的证书：

# “`
# curl –cacert /path/to/ca.crt https://example.com
# “`

# 3. 指定客户端证书和私钥：如果你需要使用客户端证书和私钥进行身份验证，可以使用CURL的”–cert”和”–key”选项来指定证书和私钥文件的路径。例如，以下命令将使用客户端证书和私钥对服务器进行身份验证：

# “`
# curl –cert /path/to/client.crt –key /path/to/client.key https://example.com
# “`

# 4. 使用证书密码：如果你的客户端证书被密码保护，你可以使用CURL的”-pass”选项来指定密码。例如，以下命令将使用密码”password”来解锁客户端证书：

# “`
# curl –cert /path/to/client.crt –key /path/to/client.key –pass “password” https://example.com
# “`

# 5. 指定证书类型：如果你的证书文件不是默认的PEM格式，你可以使用CURL的”–cert-type”选项来指定证书的类型。例如，以下命令将指定证书文件为DER格式：

# “`
# curl –cert /path/to/client.der –key /path/to/client.key –cert-type DER https://example.com
# “`

# 以上是使用CURL命令进行证书访问时的一些重要要点。根据实际情况，你可以选择使用其中的一个或多个选项来满足你的需求。CURL是一个用于发送和接收HTTP请求的命令行工具。在Linux系统中，可以使用CURL命令来访问使用SSL / TLS进行加密的网站，正常情况下会验证服务器的证书。下面是关于如何使用CURL命令进行证书访问的一些重要的要点：

# 1. 跳过SSL证书验证：如果你需要在访问某个网站时跳过SSL证书验证，可以使用-CURL的”-k”选项。例如，以下命令将跳过证书验证并访问带有自签名证书的网站：

# “`
# curl -k https://example.com
# “`

# 2. 指定CA证书文件：如果你有一个CA证书文件，你可以通过在CURL命令中使用”–cacert”选项来指定该文件的路径。例如，以下命令将使用CA证书文件来验证服务器的证书：

# “`
# curl –cacert /path/to/ca.crt https://example.com
# “`

# 3. 指定客户端证书和私钥：如果你需要使用客户端证书和私钥进行身份验证，可以使用CURL的”–cert”和”–key”选项来指定证书和私钥文件的路径。例如，以下命令将使用客户端证书和私钥对服务器进行身份验证：

# “`
# curl –cert /path/to/client.crt –key /path/to/client.key https://example.com
# “`

# 4. 使用证书密码：如果你的客户端证书被密码保护，你可以使用CURL的”-pass”选项来指定密码。例如，以下命令将使用密码”password”来解锁客户端证书：

# “`
# curl –cert /path/to/client.crt –key /path/to/client.key –pass “password” https://example.com
# “`

# 5. 指定证书类型：如果你的证书文件不是默认的PEM格式，你可以使用CURL的”–cert-type”选项来指定证书的类型。例如，以下命令将指定证书文件为DER格式：

# “`
# curl –cert /path/to/client.der –key /path/to/client.key –cert-type DER https://example.com
# “`

# 以上是使用CURL命令进行证书访问时的一些重要要点。根据实际情况，你可以选择使用其中的一个或多个选项来满足你的需求。

.PHONY: health
health:
	@curl -k -v -X GET https://api.acme.com/health --http2 -H "Content-Type: application/json"
