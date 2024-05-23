package main

import (
	"fmt"
	"testing"
	"time"
)

func TestGetIp(t *testing.T) {
	// 获取当前文件夹路径
	// 获取当前时间
	currentTime := time.Now()

	// 将时间转换为毫秒级时间戳
	milliseconds := currentTime.UnixNano() / int64(time.Millisecond)

	fmt.Println("当前的毫秒级时间戳：", milliseconds)
}
