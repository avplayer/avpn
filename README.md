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

在win上安装好tap-windows之后，便会在系统上创建一个虚拟网卡设备，我为了避免和其它虚拟网卡设备
冲突，我将其重命名为 VPN01（具体操作就是在 控制面板\网络和 Internet\网络连接 找到这个设备，
然后右击选择重命名）。

然后编译该项目，生成 avpn.exe
执行命令

avpn.exe 虚拟网卡的名字 socks5://1.1.1.1:1080

便可启动avpn


但这时所有数据包走的是默认本地网络，而不是虚拟网卡，这时
我们需要调整路由表来实现默认走虚拟网卡，只有socks5://1.1.1.1:1080
走本地连接.

具体操作：
打开具有管理员权限的powershell或cmd，这里假设我的出口网卡设备名是 WLAN，出口网关是
192.168.125.1
然后执行命令：

netsh interface ip set interface WLAN ignoredefaultroutes = enabled

上面命令是忽略指定网卡接口的默认路由，这里是忽略WLAN

route add 1.1.1.1 192.168.125.1 metric 1

这里是将socks的服务器ip指定路由到192.168.125.1

route add 0.0.0.0 mask 0.0.0.0 10.0.0.2 metric 5

这是将所有数据都将走10.0.0.2，因为我们的虚拟网卡接口的网关就是10.0.0.2，10.0.0.2它是
一个并不实际存在的，目的主要是将所有ip数据都通过这个虚拟网卡接口.

这时，成功启动avpn并修改了路由之后, 我们便可以执行curl来测试vpn的运行了, 如:

curl -v http://api.ipify.org/

这时看到的ip应该是代理服务器的ip地址，我们成功的将本机所有数据都通过avpn经socks协议代理
到socks服务器.

注意：代理服务器请使用本人开发的 https://github.com/avplayer/socks_server ，因为它实现
了udp转发，而一般的socks服务器对udp的实现并不完善，否则的话，可能因为dns无法解析，导致访
问任何域名将解析不会成功。

