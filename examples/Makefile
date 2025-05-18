# curl 可以发送http2请求，restclient 不行

.PHONY: health
health:
	@curl -k -v -X GET https://api.acme.com/health --http2 -H "Content-Type: application/json"

.PHONY: create-user
create-user:
	@curl -k -X POST https://api.acme.com/users \
		--http1.1 \
		-H "Content-Type: application/json" \
		-H "Accept: application/json" \
		-d '{"name": "测试用户", "email": "test@example.com", "password": "password123"}'

.PHONY: get-users
get-users:
	@curl -k -v -X GET https://api.acme.com/users

.PHONY: get-user
get-user:
	@echo "请先执行make create-user获取userId，然后替换下面的<userId>"
	@curl -k -v -X GET https://api.acme.com/users/<userId>

.PHONY: update-user
update-user:
	@echo "请先执行make create-user获取userId，然后替换下面的<userId>"
	@curl -k -v -X PUT https://api.acme.com/users/<userId> \
		-H "Content-Type: application/json" \
		-H "Accept: application/json" \
		-d '{"name": "更新后的名字", "email": "updated@example.com"}'

.PHONY: delete-user
delete-user:
	@echo "请先执行make create-user获取userId，然后替换下面的<userId>"
	@curl -k -v -X DELETE https://api.acme.com/users/<userId>

.PHONY: test-error
test-error:
	@curl -k -v -X GET https://api.acme.com/users/9999
