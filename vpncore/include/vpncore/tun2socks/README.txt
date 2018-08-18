这里基于vpncore的一个tun2socks实现.

socks_client.hpp 是socks客户端的具体实现.
tun2socks.hpp 是tun2socks的具体实现.

工作原理:
  主要是用vpncore里的demultiplexer, 用它来
async_accept一个tcp_stream, 在handle_accept
回调时, 创建socks_client对象连接socks代理
服务器, 连接成功再在收到accept的tcp_stream对
象上执行accept(tcp_stream::ac_deny), 表示接
收连接, 在此之后, 就是从tcp_stream对象上读
取数据并把数据转发给socks_clent, 与此同时也
读取socks_client上的数据转发给tcp_stream,
这样就完成了整个tcp数据通过vpn到代理, 代理到
vpn的整个实现.
