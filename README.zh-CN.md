# 基于 Pingora 的简易反向代理

[English Document](README.md) | [中文文档](README.zh-CN.md)

使用 Cloudflare [Pingora](https://github.com/cloudflare/pingora) 构建的高性能 HTTP/HTTPS 代理，可转发请求至示例的 Axum Web 服务器。

## 功能特性

**代理服务 (main.rs/lib.rs)**
- 支持 HTTP/1.1 和 HTTP/2
- 请求/响应头修改
- 上游连接池
- 添加自定义头信息：
  - `X-Simple-Version`: 代理版本
  - `User-Agent`: 代理标识
  - `Server`: 隐藏上游服务器信息

**示例后端 (server.rs)**
- 用户管理 REST API
- 基于内存存储 (DashMap) 的 CRUD 操作
- 使用 Argon2 的安全密码哈希
- 请求/响应日志记录
- 健康检查端点
- 完整的测试覆盖

## 环境要求
- Rust 1.75+
- Cargo
- OpenSSL

## 快速开始

```bash
git clone https://github.com/yourusername/simple-proxy.git
cd simple-proxy
# 启动代理服务（端口 8080）
RUST_LOG=info cargo run --release

# 另起终端启动示例服务器（端口 3000）
RUST_LOG=info cargo run --example server
