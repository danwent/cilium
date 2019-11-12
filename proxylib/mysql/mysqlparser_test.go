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

package mysql

import (
	"encoding/hex"
	"testing"

	// "github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/proxylib/accesslog"
	"github.com/cilium/cilium/proxylib/proxylib"
	"github.com/cilium/cilium/proxylib/test"

	// log "github.com/sirupsen/logrus"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	// logging.ToggleDebugLogs(true)
	// log.SetLevel(log.DebugLevel)

	TestingT(t)
}

type MySQLSuite struct {
	logServer *test.AccessLogServer
	ins       *proxylib.Instance
}

var _ = Suite(&MySQLSuite{})

// Set up access log server and Library instance for all the test cases
func (s *MySQLSuite) SetUpSuite(c *C) {
	s.logServer = test.StartAccessLogServer("access_log.sock", 10)
	c.Assert(s.logServer, Not(IsNil))
	s.ins = proxylib.NewInstance("node1", accesslog.NewClient(s.logServer.Path))
	c.Assert(s.ins, Not(IsNil))
}

func (s *MySQLSuite) checkAccessLogs(c *C, expPasses, expDrops int) {
	passes, drops := s.logServer.Clear()
	c.Check(passes, Equals, expPasses, Commentf("Unxpected number of passed access log messages"))
	c.Check(drops, Equals, expDrops, Commentf("Unxpected number of passed access log messages"))
}

func (s *MySQLSuite) TearDownTest(c *C) {
	s.logServer.Clear()
}

func (s *MySQLSuite) TearDownSuite(c *C) {
	s.logServer.Close()
}

// util function used for MySQL tests, as we have postresql requests
// as hex strings
func hexData(c *C, dataHex ...string) [][]byte {
	data := make([][]byte, 0, len(dataHex))
	for i := range dataHex {
		dataRaw, err := hex.DecodeString(dataHex[i])
		c.Assert(err, IsNil)
		data = append(data, dataRaw)
	}
	return data
}

func (s *MySQLSuite) TestMySQLOnDataPartialHdr(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp6"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "mysql"
		    l7_rules: <
		      l7_rules: <
			rule: <
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "mysql", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp6")

	data := hexData(c, "0000")
	conn.CheckOnDataOK(c, false, false, &data, []byte{}, proxylib.MORE, 4-len(data[0]))
}

// this passes a full startup request
func (s *MySQLSuite) TestMySQLOnDataAuth(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp5"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "mysql"
		    l7_rules: <
		      l7_rules: <
			rule: <
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "mysql", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp5")
	data := hexData(c, "3e00000185a603000000000121000000000000000000000000000000000000000000000074666f65727374650014eefd6d5562851bc5966a0b41236ae3f2315efcc4")
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(data[0]),
		proxylib.MORE, 4)
}

// this passes a series of valid requests
func (s *MySQLSuite) TestMySQLOnDataSelect(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp5"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "mysql"
		    l7_rules: <
		      l7_rules: <
			rule: <
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "mysql", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp5")
    req1 := "210000000373656c65637420404076657273696f6e5f636f6d6d656e74206c696d69742031"
	data1 := hexData(c, req1)
	conn.CheckOnDataOK(c, false, false, &data1, []byte{}, proxylib.PASS, (len(req1) / 2))
}
