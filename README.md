# orkestr-egress-proxy

给 codearts2api「出口代理」功能做真网验证用的最小 HTTP 转发代理，
部署在 orkestr（EU 托管）上，作为测试账号的独立出口。

- `http://` 目标：绝对 URI 转发，响应带 `x-via-orkestr-proxy: 1`
- `https://` 目标：CONNECT 隧道（命中数经 `/hits` 查询）
- 诊断：`/ip` 回显容器出口 IP、`/hits` 回显命中计数
- 鉴权：`x-proxy-token: <PROXY_TOKEN>`（或 Basic 代理认证），防开放代理滥用

部署：orkestr 项目 → 本仓库 → 环境变量 `PROXY_TOKEN=<token>` → 端口取 `PORT`。
