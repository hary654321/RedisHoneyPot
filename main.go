/*
 * @Description:
 * @Version: 2.0
 * @Autor: ABing
 * @Date: 2024-05-22 15:51:44
 * @LastEditors: lhl
 * @LastEditTime: 2024-08-12 16:08:53
 */
// @Title  main.go
// @Description High Interaction Honeypot Solution for Redis protocol
// @Author  Cy 2021.04.08
package main

import (
	"RedisHoneyPot/lib"
	"flag"
)

var (
	proto string
	num   int
)

func init() {
	flag.StringVar(&proto, "proto", "tcp", "listen proto")
	flag.IntVar(&num, "num", 1, "loops num")
	flag.Parse()
}

func main() {
	s, err := lib.NewRedisServer(proto, num)
	if err != nil {
		panic(err)
	}
	defer s.Stop()
	s.Start()
}
