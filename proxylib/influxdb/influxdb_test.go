// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package influxdb

import (
	"fmt"
	"testing"
	// "github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/proxylib/accesslog"
	"github.com/cilium/cilium/proxylib/proxylib"
	"github.com/cilium/cilium/proxylib/test"

	// log "github.com/sirupsen/logrus"
	. "gopkg.in/check.v1"
	"net/url"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	// logging.ToggleDebugLogs(true)
	// log.SetLevel(log.DebugLevel)

	TestingT(t)
}

type InfluxDBSuite struct {
	logServer *test.AccessLogServer
	ins       *proxylib.Instance
}

var _ = Suite(&InfluxDBSuite{})

// Set up access log server and Library instance for all the test cases
func (s *InfluxDBSuite) SetUpSuite(c *C) {
	s.logServer = test.StartAccessLogServer("access_log.sock", 10)
	c.Assert(s.logServer, Not(IsNil))
	s.ins = proxylib.NewInstance("node1", accesslog.NewClient(s.logServer.Path))
	c.Assert(s.ins, Not(IsNil))
}

func (s *InfluxDBSuite) checkAccessLogs(c *C, expPasses, expDrops int) {
	passes, drops := s.logServer.Clear()
	c.Check(passes, Equals, expPasses, Commentf("Unxpected number of passed access log messages"))
	c.Check(drops, Equals, expDrops, Commentf("Unxpected number of passed access log messages"))
}

func (s *InfluxDBSuite) TearDownTest(c *C) {
	s.logServer.Clear()
}

func (s *InfluxDBSuite) TearDownSuite(c *C) {
	s.logServer.Close()
}

func (s *InfluxDBSuite) TestWriteRequest(c *C) {
	// allow all rule
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp100"
		policy: 2
		ingress_per_port_policies: <
		  port: 8086
		  rules: <
		    l7_proto: "influxdb"
		  >
		>
		`})
	http_body := url.QueryEscape("mymeas,mytag=1 myfield=90")
	conn := s.ins.CheckNewConnectionOK(c, "influxdb", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:8086", "cp100")
	req1 := "POST /write?db=db2&precision=s HTTP/1.1\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(http_body)) +
		"\r\n" +
		http_body

	data := [][]byte{[]byte(req1)}
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(data[0]))
}

func (s *InfluxDBSuite) TestReadRequest(c *C) {
	// allow all rule
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp101"
		policy: 2
		ingress_per_port_policies: <
		  port: 8086
		  rules: <
		    l7_proto: "influxdb"
		  >
		>
		`})
	http_body := url.QueryEscape("q=SELECT * FROM \"mymeas\"")
	conn := s.ins.CheckNewConnectionOK(c, "influxdb", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:8086", "cp101")
	req1 := "GET /query?db=db1 HTTP/1.1\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(http_body)) +
		"\r\n" +
		http_body

	data := [][]byte{[]byte(req1)}
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(data[0]))
}

func (s *InfluxDBSuite) TestAdminRequest(c *C) {
	// allow all rule
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp102"
		policy: 2
		ingress_per_port_policies: <
		  port: 8086
		  rules: <
		    l7_proto: "influxdb"
		  >
		>
		`})
	http_body := url.QueryEscape("q=CREATE DATABASE \"mydb\"")
	conn := s.ins.CheckNewConnectionOK(c, "influxdb", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:8086", "cp102")
	req1 := "POST /query HTTP/1.1\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(http_body)) +
		"\r\n" +
		http_body

	data := [][]byte{[]byte(req1)}
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(data[0]))
}

func (s *InfluxDBSuite) TestBasicDenyByAction(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp104"
		policy: 2
		ingress_per_port_policies: <
		  port: 8086
		  rules: <
		    l7_proto: "influxdb"
		    l7_rules: <
		      l7_rules: <
			rule: <
			  key: "action"
			  value: "read"
			>
		      >
		    >
		  >
		>
		`})

	http_body := url.QueryEscape("q=CREATE DATABASE \"mydb\"")
	conn := s.ins.CheckNewConnectionOK(c, "influxdb", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:8086", "cp104")

	// this policy should be tagged as 'admin' action and rejected
	req1 := "POST /query HTTP/1.1\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(http_body)) +
		"\r\n" +
		http_body

	data := [][]byte{[]byte(req1)}
	conn.CheckOnDataOK(c, false, false, &data, []byte(InfluxDBAccessDeniedStr),
		proxylib.DROP, len(data[0]))
}

func (s *InfluxDBSuite) TestBasicDenyByDB(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp105"
		policy: 2
		ingress_per_port_policies: <
		  port: 8086
		  rules: <
		    l7_proto: "influxdb"
		    l7_rules: <
		      l7_rules: <
			rule: <
			  key: "db"
			  value: "no-match"
			>
			rule: <
			  key: "action"
			  value: "read"
			>
		      >
		    >
		  >
		>
		`})

	http_body := url.QueryEscape("q=SELECT * FROM \"mymeas\"")
	conn := s.ins.CheckNewConnectionOK(c, "influxdb", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:8086", "cp105")
	req1 := "GET /query?db=mydb HTTP/1.1\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(http_body)) +
		"\r\n" +
		http_body

	data := [][]byte{[]byte(req1)}
	conn.CheckOnDataOK(c, false, false, &data, []byte(InfluxDBAccessDeniedStr),
		proxylib.DROP, len(data[0]))
}

func (s *InfluxDBSuite) TestAllowDBByRegex(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp106"
		policy: 2
		ingress_per_port_policies: <
		  port: 8086
		  rules: <
		    l7_proto: "influxdb"
		    l7_rules: <
		      l7_rules: <
			rule: <
			  key: "db"
			  value: "my.*"
			>
			rule: <
			  key: "action"
			  value: "read"
			>
		      >
		    >
		  >
		>
		`})

	http_body := url.QueryEscape("q=SELECT * FROM \"mymeas\"")
	conn := s.ins.CheckNewConnectionOK(c, "influxdb", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:8086", "cp106")
	req1 := "GET /query?db=mydb HTTP/1.1\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(http_body)) +
		"\r\n" +
		http_body

	data := [][]byte{[]byte(req1)}
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(data[0]))
}

func (s *InfluxDBSuite) TestIncompleteRequestHeader(c *C) {
	conn := s.ins.CheckNewConnectionOK(c, "influxdb", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:8086", "cp106")
	req1 := "POST / HTTP/1.1\r\n"
	data := [][]byte{[]byte(req1)}
	conn.CheckOnDataOK(c, false, false, &data, []byte{}, proxylib.MORE, 1)
}

func (s *InfluxDBSuite) TestIncompleteRequestBody(c *C) {
	conn := s.ins.CheckNewConnectionOK(c, "influxdb", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:8086", "cp106")
	req1 := "POST / HTTP/1.1\r\n" +
		"Content-Length: 126\r\n" +
		"\r\n" +
		"foo"
	data := [][]byte{[]byte(req1)}
	conn.CheckOnDataOK(c, false, false, &data, []byte{}, proxylib.MORE, 123) // 123 bytes missing
}

func (s *InfluxDBSuite) TestDoubleRequest(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp107"
		policy: 2
		ingress_per_port_policies: <
		  port: 8086
		  rules: <
		    l7_proto: "influxdb"
		    l7_rules: <
		      l7_rules: <
			rule: <
			  key: "db"
			  value: "my.*"
			>
		      >
		    >
		  >
		>
		`})

	http_body1 := url.QueryEscape("q=SELECT * FROM \"mymeas\"")
	req1 := "GET /query?db=mydb HTTP/1.1\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(http_body1)) +
		"\r\n" +
		http_body1

	http_body2 := url.QueryEscape("q=CREATE DATABASE \"mydb\"")
	req2 := "POST /query HTTP/1.1\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(http_body2)) +
		"\r\n" +
		http_body2

	conn := s.ins.CheckNewConnectionOK(c, "influxdb", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:8086", "cp107")
	data := [][]byte{[]byte(req1 + req2)}
	conn.CheckOnDataOK(c, false, false, &data, []byte(InfluxDBAccessDeniedStr),
		proxylib.PASS, len(req1),
		proxylib.DROP, len(req2))
}
