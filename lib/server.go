// @Title  server.go
// @Description High Interaction Honeypot Solution for Redis protocol
// @Author  Cy 2021.04.08
package lib

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Allenxuxu/gev"
	"github.com/Allenxuxu/gev/connection"
	"github.com/emirpasic/gods/maps/hashmap"
	"github.com/sirupsen/logrus"
	"github.com/walu/resp"
	"gopkg.in/ini.v1"
)

type RedisServer struct {
	server  *gev.Server
	hashmap *hashmap.Map
	Config  *ini.File
	log     *logrus.Logger
}

func NewRedisServer(address string, proto string, loopsnum int) (server *RedisServer, err error) {
	Serv := new(RedisServer)
	Serv.hashmap = hashmap.New()
	config, err := LoadConfig("redis.conf")
	Serv.log = logrus.New()
	Serv.log.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: "2006-01-02 15:04:05",
	})
	if err != nil {
		panic(err)
	}
	Serv.Config = config
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
	s.WriteLog(logrus.Fields{
		"type": "scan",
	}, c)
}

func (s *RedisServer) OnMessage(c *connection.Connection, ctx interface{}, data []byte) (out []byte) {
	command := bytes.NewReader(data)
	if command.Len() == 2 {
		return
	}
	cmd, err := resp.ReadCommand(command)
	if err != nil {
		return
	}

	com := strings.ToLower(cmd.Name())

	var extend map[string]interface{}

	extend = make(map[string]interface{})

	cmdstr := strings.Join(cmd.Args, " ")

	extend["cmd"] = cmdstr

	type1 := "op"

	_, bool := s.hashmap.Get(c.PeerAddr())

	//已登录执行命令
	if bool {

		s.WriteLog(logrus.Fields{
			"extend": extend,
			"type":   type1,
		}, c)
		out = s.dealCmd(com, cmd.Args)

		return
	}

	//未登录  只能执行登录操作
	if com != "auth" {
		out = []byte("-NOAUTH Authentication required.\r\n")

		return
	}

	pwd := ""
	type1 = "login"

	pwd = SubString(cmdstr, " ", "")
	extend["password"] = pwd
	extend["username"] = "-" //

	// fmt.Println(pwd, s.Config.Section("info").Key("requirepass").Value())
	if pwd == s.Config.Section("info").Key("requirepass").Value() {

		out = []byte("+OK\r\n")

		//设置登录成功
		s.hashmap.Put(c.PeerAddr(), 1)

	} else {
		out = []byte("-ERR invalid password\r\n")
	}

	s.WriteLog(logrus.Fields{
		"extend": extend,
		"type":   type1,
	}, c)

	return
}

func (s *RedisServer) dealCmd(com string, Args []string) (out []byte) {
	switch com {
	case "auth":

	case "ping":
		out = []byte("+PONG\r\n")
	case "info":
		info := ""
		for _, key := range s.Config.Section("info").KeyStrings() {
			info += fmt.Sprintf("%s:%s\r\n", key, s.Config.Section("info").Key(key))
		}
		out = []byte("$" + strconv.Itoa(len(info)) + "\r\n" + info + "\r\n")
	case "set":
		if len(Args) < 3 {
			out = []byte("-ERR wrong number of arguments for '" + Args[0] + "' command\r\n")
		} else {
			s.hashmap.Put(Args[1], Args[2])
			out = []byte("+OK\r\n")
		}
	case "get":
		if len(Args) != 2 {
			out = []byte("-ERR wrong number of arguments for '" + Args[0] + "' command\r\n")
		} else {
			v, bool := s.hashmap.Get(Args[1])
			if bool == true {
				out = []byte("+" + v.(string) + "\r\n")
			} else {
				out = []byte("+(nil)\r\n")
			}
		}
	case "del":
		if len(Args) < 2 {
			out = []byte("-ERR wrong number of arguments for '" + Args[0] + "' command\r\n")
		} else {
			s.hashmap.Remove(Args[1])
			out = []byte("+(integer) 1\r\n")
		}
	case "exists":
		if len(Args) < 2 {
			out = []byte("-ERR wrong number of arguments for '" + Args[0] + "' command\r\n")
		} else {
			_, bool := s.hashmap.Get(Args[1])
			if bool == true {
				out = []byte("+(integer) 1\r\n")
			} else {
				out = []byte("+(integer) 0\r\n")
			}
		}
	case "keys":
		if len(Args) != 2 {
			out = []byte("-ERR wrong number of arguments for '" + Args[0] + "' command\r\n")
		} else {
			if Args[1] == "*" {
				str := "*" + strconv.Itoa(s.hashmap.Size()) + "\r\n"
				for _, v := range s.hashmap.Keys() {
					str += "$" + strconv.Itoa(len(v.(string))) + "\r\n" + v.(string) + "\r\n"
				}
				out = []byte(str)
			} else {
				_, bool := s.hashmap.Get(Args[1])
				if bool == true {
					l := strconv.Itoa(len(Args[1]))
					out = []byte("*1\r\n$" + l + "\r\n" + Args[1] + "\r\n")
				} else {
					out = []byte("+(empty array)\r\n")
				}
			}
		}
	case "flushall":
		out = []byte("+OK\r\n")
	case "flushdb":
		out = []byte("+OK\r\n")
	case "save":
		out = []byte("+OK\r\n")
	case "select":
		out = []byte("+OK\r\n")
	case "dbsize":
		l := strconv.Itoa(s.hashmap.Size())
		out = []byte("+(integer) " + l + "\r\n")
	case "config":
		if Args[1] == "get" && len(Args) > 2 {
			if Args[2] != "*" {
				content := s.Config.Section("info").Key(Args[2]).String()
				if content == "" {
					out = []byte("+(empty array)\r\n")
				} else {
					l1 := strconv.Itoa(len(Args[2]))
					l2 := strconv.Itoa(len(content))
					out = []byte("*2\r\n$" + l1 + "\r\n" + Args[2] + "\r\n$" + l2 + "\r\n" + content + "\r\n")
				}
			} else {
				output := "*" + strconv.Itoa(len(s.Config.Section("info").KeyStrings())*2) + "\r\n"
				for _, key := range s.Config.Section("info").KeyStrings() {
					value := s.Config.Section("info").Key(key).String()
					output += "$" + strconv.Itoa(len(key)) + "\r\n" + key + "\r\n" + "$" + strconv.Itoa(len(value)) + "\r\n" + value + "\r\n"
				}
				out = []byte(output)
			}
		} else if Args[1] == "set" && len(Args) > 2 {
			s.Config.Section("info").NewKey(Args[2], Args[3])
			out = []byte("+OK\r\n")
		} else {
			out = []byte("-ERR Unknown subcommand or wrong number of arguments for 'get'. Try CONFIG HELP.\r\n")
		}
	case "slaveof":
		if len(Args) < 3 {
			out = []byte("-ERR wrong number of arguments for 'slaveof' command\r\n")
		} else {
			out = []byte("+OK\r\n")
		}
	default:
		out = []byte("-ERR unknown command `" + com + "`, with args beginning with:\r\n")
	}

	return
}

func (s *RedisServer) OnClose(c *connection.Connection) {
	s.WriteLog(logrus.Fields{
		"type": "close",
	}, c)
}

func (s *RedisServer) WriteLog(fields logrus.Fields, c *connection.Connection) {

	// localHost, localPort, _ := net.SplitHostPort(c.LocalAddr().String())
	remoteHost, remotePort, _ := net.SplitHostPort(c.PeerAddr())

	port, _ := strconv.Atoi(remotePort)

	fields["protocol"] = "tcp"
	fields["name"] = "redis"
	fields["app"] = "redis"
	fields["src_ip"] = remoteHost
	fields["src_port"] = port
	fields["dest_ip"] = Getip()
	fields["dest_port"] = 6379

	currentTime := time.Now()

	// 将时间转换为毫秒级时间戳
	milliseconds := currentTime.UnixNano() / int64(time.Millisecond)
	fields["timestamp"] = milliseconds
	fields["UUID"] = "<UUID>"

	s.log.WithFields(fields).Println()
}

func SubString(str, s, e string) string {
	start := 0
	if s != "" {
		start = strings.Index(str, s) + len(s)
	}
	end := 0
	if e == "" {
		end = len(str)
	} else {
		end = strings.Index(str, e)
	}
	substring := str[start:end]

	return substring
}

func Getip() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("获取网络接口信息失败:", err)
		return ""
	}

	for _, iface := range interfaces {

		// fmt.Println(iface.Flags.String())

		addrs, err := iface.Addrs()
		if err != nil {
			fmt.Println("获取网络接口地址失败:", err)
			continue
		}

		for _, addr := range addrs {
			// fmt.Println(addr)

			ip, _, _ := net.ParseCIDR(addr.String())

			if ip.To4() != nil {

				ipstr := ip.String()

				//todo
				if strings.HasSuffix(ipstr, "0.1") {
					continue
				}

				return ipstr
			}
		}
	}

	return ""
}
