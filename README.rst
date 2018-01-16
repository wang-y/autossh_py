autossh
======

用python完成的一个简单的基于expect链接远程主机的工具，只用首次连接时输入相关的登录信息（IP地址、用户名、密码、端口）
过后只需通过指定HOSTNAME/IP即可

.. code-block:: bash

    # 安装
    bash build.sh ~/.zshrc

    # 用法
    autossh HOSTNAME:IP USERNAME PASSWORD PORT

    # 第一次连接
    autossh mypc:192.168.1.99 root root 22

    # 再次连接
    autossh 192.168.1.99  或者  autossh mypc

    # 卸载
    ./remove.sh

以上全是抄袭+魔改

原版地址： https://github.com/Agnewee/atssh.git
