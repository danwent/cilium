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

package postgresql

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

type PostgreSQLSuite struct {
	logServer *test.AccessLogServer
	ins       *proxylib.Instance
}

var _ = Suite(&PostgreSQLSuite{})

// Set up access log server and Library instance for all the test cases
func (s *PostgreSQLSuite) SetUpSuite(c *C) {
	s.logServer = test.StartAccessLogServer("access_log.sock", 10)
	c.Assert(s.logServer, Not(IsNil))
	s.ins = proxylib.NewInstance("node1", accesslog.NewClient(s.logServer.Path))
	c.Assert(s.ins, Not(IsNil))
}

func (s *PostgreSQLSuite) checkAccessLogs(c *C, expPasses, expDrops int) {
	passes, drops := s.logServer.Clear()
	c.Check(passes, Equals, expPasses, Commentf("Unxpected number of passed access log messages"))
	c.Check(drops, Equals, expDrops, Commentf("Unxpected number of passed access log messages"))
}

func (s *PostgreSQLSuite) TearDownTest(c *C) {
	s.logServer.Clear()
}

func (s *PostgreSQLSuite) TearDownSuite(c *C) {
	s.logServer.Close()
}

// util function used for PostgreSQL tests, as we have postresql requests
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

func (s *PostgreSQLSuite) TestPostgreSQLOnDataPartialStartupHdr(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp6"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "postgresql"
		    l7_rules: <
		      l7_rules: <
			rule: <
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "postgresql", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp6")

	data := hexData(c, "0000")
	conn.CheckOnDataOK(c, false, false, &data, []byte{}, proxylib.MORE, 5-len(data[0]))
}

// this passes a full startup request
func (s *PostgreSQLSuite) TestPostgreSQLOnDataMultipleReq(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp5"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "postgresql"
		    l7_rules: <
		      l7_rules: <
			rule: <
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "postgresql", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp5")
	data := hexData(c, "000000260003000075736572006f727978006461746162617365006d61696c73746f72650000")
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(data[0]),
		proxylib.MORE, 5)
}

// this passes a series of valid requests
func (s *PostgreSQLSuite) TestPostgreSQLOnDataMultipleRequests(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp5"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "postgresql"
		    l7_rules: <
		      l7_rules: <
			rule: <
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "postgresql", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp5")
	req1 := "000000260003000075736572006f727978006461746162617365006d61696c73746f72650000"
	data1 := hexData(c, req1)
	conn.CheckOnDataOK(c, false, false, &data1, []byte{}, proxylib.PASS, (len(req1) / 2))
	
	//TODO:  need to send reply so that 'startup_complete' is set to true for the parser
	req2 := "70000000286d6435636566666330316463646537353431383239646565663662356539633931343200"
        req3 := "500000000d00626567696e000000420000000e000000000000000100014500000009000000000050000000310073656c656374207265766973696f6e2066726f6d206d61696c73746f726520666f7220757064617465000000420000000e0000000000000001000144000000065000450000000900000000005300000004"
	data2 := hexData(c, req2 + req3)
	conn.CheckOnDataOK(c, false, false, &data2, []byte{},
		proxylib.PASS, (len(req2) / 2),
		proxylib.PASS, 14, // Parse
		proxylib.PASS, 15, // Bind
		proxylib.PASS, 10, // Execute
		proxylib.PASS, 50, // Parse
		proxylib.PASS, 15, // Bind
		proxylib.PASS, 7, // Describe
		proxylib.PASS, 10, // Execute
		proxylib.PASS, 5, // Sync
		proxylib.MORE, 5)
}
