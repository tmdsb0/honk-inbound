# 链式代理（detour）与 MASQUE 配置指南

本页说明 `6106757-lab/honk` 定制版的链式代理与 MASQUE 出站配置方法。上游 `daeuniverse/honk` 不含这些功能；字段语义以本仓库代码为准。适用于 `v0.1.0-beta.5-31-ge075e069` 及之后的构建。

## 1. 两个层级

| 层级 | 写法 | 作用范围 | 解析时机 |
| --- | --- | --- | --- |
| 节点级 | 分享链接 `?dialer-proxy=front`，或订阅里的 `dialer-proxy` / `detour` | 该节点自己的所有拨号 | 每代构建时绑定到节点运行时，重载时可重绑 |
| 组级 | 组块内 `detour: front` | 经过该组的流量（该组所选成员） | **每次拨号时**解析，前置换成员立即生效 |

`front` 可以是节点名、组名或 `direct`（显式直连）。名称在加载时校验；未知名称与组间成环会被拒绝或告警。

**不要混用**：同一节点既写了自身 detour、又落在带 `detour:` 的组里时，经过该组的流量按组指定的前置拨号。建议二选一，避免语义混淆。

## 2. 最小可运行示例

节点由订阅提供，配置里只写组与路由：

```dae
subscription {
    # 订阅里同时包含前置节点 front-tw 与末端 MASQUE(WARP) 节点
    mysub: 'https://example.com/sub'
}

group {
    # 前置组：改这里的成员就能换前置，热重载即生效
    qianzhi {
        filter: name('front-tw')
        policy: selector
    }

    # 末端组：所有成员都经前置组出站
    Final {
        filter: name(keyword: 'WARP')
        policy: selector
        detour: qianzhi
    }

    # 引用组：成员来自 Final，自动继承 Final 的 detour
    Proxy {
        filter: group(Final)
        policy: selector
    }

    Google {
        filter: group(Final)
        policy: selector
    }

    # 显式覆盖：这个组直连，不继承
    Local {
        filter: group(Final)
        detour: direct
        policy: selector
    }
}

routing {
    domain(geosite: google) -> Google
    domain(geosite: geolocation-!cn) -> Proxy
    fallback: Final
}
```

`Proxy` / `Google` 没有写 `detour`，但 `filter: group(Final)` 是**引用边**而不是拷贝节点列表，因此会按声明顺序向上游查找并继承 `Final` 的 `qianzhi`。`Local` 写了 `detour: direct`，显式覆盖并停止继承。

## 3. 节点级写法

手写 `node {}` 时用查询参数指定前置：

```dae
node {
    landing: 'vless://uuid@example.com:443?dialer-proxy=qianzhi#Landing'
}
```

查询参数接受 `dialer-proxy`、`dialer_proxy`、`detour`、`underlying-proxy`、`underlying_proxy`；空值视为不指定。

订阅里：

- Clash / Mihomo YAML：节点条目写 `dialer-proxy: qianzhi`（也接受 `dialer_proxy` / `detour`）。
- sing-box JSON：出站对象写 `"detour": "qianzhi"`。

节点级 detour 在 TCP 和 UDP 上都生效，包括 QUIC 类（Hysteria2 / TUIC / Juicity）与 MASQUE。前置写成组时，Selector 切换或 Fallback 故障转移也会立刻改变后续拨号的前置。

目标域名解析出多个地址时，走 detour 的拨号会像直连拨号一样对全部地址竞速，先通者胜；排第一的地址不通不再导致整个拨号失败。

## 4. 组级写法与继承

```dae
group {
    Final {
        filter: name('WARP')
        detour: qianzhi     # 节点名或组名；direct 表示显式直连
    }
}
```

- 解析集中在 `group_detour()` 一处：TCP 拨号、UDP 拨号、Clash API 与原生 API 的延迟测试共用同一结果，测到的是真实业务链路。
- 命中组自身没有 `detour:` 时，沿 `filter: group(X)` 的引用边做广度优先查找，按声明顺序取第一个；有 `visited` 防环；显式 `detour:`（含 `direct`）优先并停止查找。
- `final:` 是策略无合格选择时的回退，**不继承** detour。
- 没有 `group()` 引用边、而是用 `name()` / `subtag()` 直接过滤出来的组，不会凭空继承。

## 5. MASQUE 节点

MASQUE（RFC 9298 connect-ip）把 IP 包放进 HTTP/2 或 HTTP/3 隧道，并在本机创建 TUN 设备。主要经订阅导入：

```yaml
proxies:
  - name: "WARP"
    type: masque
    server: 162.159.199.2
    port: 443
    network: h2            # 或 quic，缺省 h2
    private-key: "..."     # WARP 设备私钥（Base64）
    public-key: "..."      # 端点公钥（可选）
    ip: 172.16.0.2         # 隧道内 IPv4；省略时由 ADDRESS_ASSIGN 分配
    ipv6: "..."            # 可选
    mtu: 1280              # WARP 常用值
    remote-dns-resolve: false
    sni: "..."             # MASQUE 强制 TLS
```

- 也识别 `masque://host:port` 形式的手写分享链接；WARP 所需的密钥等字段请以订阅 YAML 提供。
- 内置网页界面（本组织编译的 doona `v0.1.0-rc.4`）支持对 MASQUE 节点做延迟测试。探针使用独立的高位 TUN 槽位，不会抢占业务隧道的 TUN 设备与默认路由。
- 一个 MASQUE tunnel 就是一条到端点的 carrier 连接，因此**每条路径各自持有 tunnel**（各自的 TUN 设备与默认路由 metric）。走前置与直连的流量不会共用同一个 tunnel。
- 节点级 detour 指向另一个 MASQUE 节点会被忽略并告警（会嵌套 tunnel）；组级 detour 也应避免把 MASQUE 节点当前置。

## 6. 热切换与重载

改前置节点或前置组成员后，`kill -HUP <MainPID>`（或界面里的配置重载）即可生效，**不需要重启 honk**。实现上：

- 节点运行时的 detour 绑定可在每一代重新绑定或清除；
- MASQUE tunnel 缓存键包含实际承载节点，前置变化即重建 tunnel 并释放旧 TUN；
- 空闲 tunnel 在重载事务提交后回收，仍被活跃连接持有的 tunnel 按设计保留；
- UI 延迟测试与 Clash API `delay` 走同一路径，切换前置后测得的延迟会跟着变。

## 7. 协议支持与边界

| 协议 | TCP 组 detour | UDP 组 detour |
| --- | --- | --- |
| SOCKS5 / Shadowsocks / Trojan / VMess / VLESS（普通流） / AnyTLS | 支持 | 支持（AnyTLS 为私有 session） |
| Hysteria2 / TUIC / Juicity | 支持 | 支持（私有 QUIC client） |
| MASQUE | 支持 | 支持（每路径独立 tunnel，socket 持有 tunnel） |
| VLESS H2 / Cool / XUDP | 明确拒绝 | 明确拒绝 |

- 不支持的协议会**拒绝拨号并记日志**，不会静默直连；日志出现 `cannot carry a detour` 时请换协议或去掉该组的 `detour:`。
- honk 自身发起的流量（DoH、订阅 / geodata 下载）由各自的 `route` / `download_detour` 控制，**不受组 detour 影响**。
- `detour: direct` 可让某个引用组显式绕过前置。

## 8. 怎么确认真的走了前置

1. 用命中带 detour 的组的流量触发。例如裸 IP `curl -k https://1.1.1.1/cdn-cgi/trace` 会落到 `Final`；不要用会命中别的组的域名当判据。
2. `ss -tnp` 看是否新增到前置节点的连接。健康探测也会直连节点端点，别把探测连接当成业务直连。
3. 决定性对照：只删除 `Final` 的 `detour:` 并热重载，观察 MASQUE TUN 上 socket 的落点是否从旧的 `masq...0` 换到新开的 `masq...1`；恢复后再换回来。TUN 设备名是动态分配的，**不能靠设备名猜哪条走前置**。
4. 在 UI 里对 MASQUE 节点点延迟测试，数值应反映「前置 + 末端」整条链路。

## 9. 常见问题

- **一部分流量没走前置**：检查这些流量命中的组是否有 `filter: group(X)` 引用边。没有引用边的组不会继承；给它们补 `detour:` 或改成引用 `Final`。
- **UDP / QUIC 没走前置**：本版本已把组 detour 贯通 UDP 数据面；若仍异常，确认末端协议不在上表「明确拒绝」之列。
- **改了前置要重启才生效**：本版本已修复，只做热重载即可。若现象仍在，检查改的是不是订阅里的节点级 `dialer-proxy`（需等订阅刷新）。
- **UI 里 MASQUE 不能测延迟**：确认用的是本仓库的 `full` 构建（内置 `v0.1.0-rc.4` 版 doona）。

## 相关文档

- [节点参考](../reference/nodes.md)
- [组参考](../reference/groups.md)
- [配置指南](../configuration.md)
