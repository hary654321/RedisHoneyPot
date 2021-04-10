// @Title  main.go
// @Description A highly interactive honeypot supporting redis protocol
// @Author  Cy 2021.04.08
package main

import (
	"bytes"
	"github.com/Allenxuxu/gev"
	"github.com/Allenxuxu/gev/connection"
	"github.com/emirpasic/gods/maps/hashmap"
	"github.com/walu/resp"
	"log"
)

var (
	err error
)

type RedisServer struct {
	server  *gev.Server
	hashmap *hashmap.Map
}

func NewRedisServer(address string, proto string, loopsnum int) (server *RedisServer, err error) {
	Serv := new(RedisServer)
	Serv.hashmap = hashmap.New()
	Serv.server, err = gev.NewServer(Serv,
		gev.Address(address),
		gev.Network(proto),
		gev.NumLoops(loopsnum))
	if err != nil {
		return nil, err
		panic(err)
	}
	return Serv, nil
}

func (s *RedisServer) Start() {
	s.server.Start()
}

func (s *RedisServer) Stop() {
	s.server.Stop()
}

func (s *RedisServer) OnConnect(c *connection.Connection) {
	log.Println(" New connection from : ： ", c.PeerAddr())
}

func (s *RedisServer) OnMessage(c *connection.Connection, ctx interface{}, data []byte) (out []byte) {
	out = data
	command := bytes.NewReader(data)
	cmd, err := resp.ReadCommand(command)
	if err != nil {
		out = data
	}
	switch cmd.Name() {
	case "ping":
		out = []byte("+PONG\r\n")
	case "info":

	case "set":
		s.hashmap.Put(cmd.Args[1], cmd.Args[2])
		out = []byte("+OK\r\n")
	case "get":
		v, bool := s.hashmap.Get(cmd.Args[1])
		if bool == true {
			out = []byte("+" + v.(string) + "\r\n")
		} else {
			out = []byte("+(nil)\r\n")
		}
	case "del":
		s.hashmap.Remove(cmd.Args[1])
		out = []byte("+(integer) 1\r\n")
	default:
		out = []byte("-ERR unknown command " + cmd.Name() + "\r\n")
	}
	return
}

func (s *RedisServer) OnClose(c *connection.Connection) {
	log.Println(c.PeerAddr(), "Closed")
}
