一个简单的vpn的实现
=====================


目前尚处于开发状态，所以下面介绍一下一些简单的测试调试方法：

准备一个socks server服务器，这里我们假定为

socks5://1.1.1.1:1080

在win上下载安装tap-windows驱动(linux内核一般自带tun驱动所以不需要安装任何驱动)，并创建虚拟网卡
tap-windows下载位置在
https://openvpn.net/index.php/open-source/downloads.html
的最下面，我这里下载的是
tap-windows-9.21.2.exe
根据os情况选择版本.


然后编译该项目，生成 avpn.exe
执行命令

avpn.exe 虚拟网卡的名字 socks5://1.1.1.1:1080

便可启动avpn


但这时所有数据包走的是默认本地网络，而不是虚拟网卡，这时
我们需要调整路由表来实现默认走虚拟网卡，只有socks5://1.1.1.1:1080
走本地连接.

成功启动avpn并修改了路由之后, 我们便可以执行curl来测试vpn的运行了, 如:

curl -v http://api.ipify.org/

这时看到的ip应该是代理的ip地址.

如果不想对系统路由做任何修改, 可以指定网卡为虚拟网卡来测试vpn的工作, 如:

curl -v --interface 10.0.0.1 http://api.ipify.org/

结果同上

