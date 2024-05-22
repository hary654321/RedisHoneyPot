package main

import (
	"fmt"
	"net"
	"testing"
)

func TestGetIp(t *testing.T) {
	// 获取当前文件夹路径

	Println(Getip())
}

func Getip() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("获取网络接口信息失败:", err)
		return ""
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			fmt.Println("获取网络接口地址失败:", err)
			continue
		}

		for _, addr := range addrs {
			ip, _, _ := net.ParseCIDR(addr.String())
			if ip.To4() != nil {
				return ip.String()
			}
		}
	}

	return ""
}
