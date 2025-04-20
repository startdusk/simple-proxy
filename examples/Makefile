# curl 可以发送http2请求，restclient 不行
.PHONY: health
health:
	@curl -X GET http://localhost:8080/health --http2 -H "Content-Type: application/json"
