// Copyright 2019 Authors of Cilium
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

package mysql

import (
	"bytes"
	"encoding/binary"
    "encoding/hex"
    "regexp"

	. "github.com/cilium/cilium/proxylib/proxylib"

	"github.com/cilium/proxy/go/cilium/api"
	log "github.com/sirupsen/logrus"
)

//
// MySQL Visibility Parser
//
//  Note: this is a very basic parser, intended only for visibility
// (i.e., there is no filtering).  Currently only requests are logged
// and only high-level information about the requests are logged,
// namely, the "type" of the request, and if it is a Query request,
// the Query string.
//
// References on PostgreSQL protocol:
// - https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_PROTOCOL.html
// - https://wiki.wireshark.org/SampleCaptures#MySQL_protocol

type MySQLRule struct {
	queryActionExact   string
	tableRegexCompiled *regexp.Regexp
}

func (rule *MySQLRule) Matches(data interface{}) bool {
    // no policy for now
	return true
}

// MySQLRuleParser parses protobuf L7 rules to enforcement objects
// May panic
func MySQLRuleParser(rule *cilium.PortNetworkPolicyRule) []L7NetworkPolicyRule {
	var rules []L7NetworkPolicyRule
	l7Rules := rule.GetL7Rules()
	if l7Rules == nil {
		return rules
	}
	return rules
}

type MySQLParserFactory struct{}

var mySQLParserFactory *MySQLParserFactory

func init() {
	log.Debug("init(): Registering mySQLParserFactory")
	RegisterParserFactory("mysql", mySQLParserFactory)
	RegisterL7RuleParser("mysql", MySQLRuleParser)
}

type MySQLParser struct {
	connection *Connection
	inserted   bool
}

func (pf *MySQLParserFactory) Create(connection *Connection) Parser {
	log.Debugf("MySQLParserFactory: Create: %v", connection)

	p := MySQLParser{connection: connection}
	return &p
}

// header is 3 byte length plus 1 byte
// seq number
const mysqlHdrLen = 4

var cmdMap = map[byte]string{
    0x00: "Sleep",
    0x01: "Quit",
    0x02: "Init DB",
    0x03: "Query",
	0x04: "Show Fields",
    0x05: "Create DB",
    0x06: "Drop DB",
    0x07: "Refresh",
    0x08: "Shutdown",
    0x09: "Statistics",
    0x0a: "Process Info",
    0x0b: "Connect",
    0x0c: "Process Kill",
    0x0d: "Debug",
    0x0e: "Ping",
    0x0f: "Time",
    0x10: "Delay Insert",
    0x11: "Change User",
    0x12: "Binlog Dump",
    0x13: "Table Dump",
    0x14: "Connect Out",
    0x15: "Register Slave",
    0x16: "Statement Prepare",
    0x17: "Statement Execute",
    0x18: "Statement Send Long Data",
    0x19: "Statement Close",
    0x1a: "Statement Reset",
    0x1b: "Set Option",
    0x1c: "Statement Fetch",
}

func (p *MySQLParser) OnData(reply, endStream bool, dataArray [][]byte) (OpType, int) {

	// inefficient, but simple for now
	data := bytes.Join(dataArray, []byte{})

    log.Infof("OnData length %d, reply = %t", len(data), reply)
	hex_str := make([]byte, hex.EncodedLen(len(data)))
	hex.Encode(hex_str, data)
    log.Infof("OnData: ==> '%s'", hex_str)

    if len(data) < mysqlHdrLen {
		// Partial header received, ask for more
		needs := mysqlHdrLen - len(data)
		log.Infof("Did not receive full packet header, need %d more bytes", needs)
		return MORE, needs
	}


    // full header available, read full request length
	log.Infof("Trying to parse requestLength")
	requestLen := binary.LittleEndian.Uint32(append(data[0:3], 0x0))

    if reply {

        return PASS, mysqlHdrLen + int(requestLen)
	}


	log.Infof("Request length = %d", requestLen)
	dataMissing := (int(requestLen) + mysqlHdrLen) - len(data)
	if dataMissing > 0 {
		// full header received, but only partial request

		log.Infof("Hdr received, but need %d more bytes of request", dataMissing)
		return MORE, dataMissing
	}

    // if seq number is not 0, pass full packet
    if  (data[3] != 0) {
        return PASS, mysqlHdrLen + int(requestLen)
    }
    var requestCmd byte = data[4]

	log.Infof("Request cmd = %d", requestCmd)
    cmdStr, ok := cmdMap[requestCmd]
    if !ok {
        cmdStr = "Unknown command code: " + string(requestCmd)
    }

    // TODO:  Add query parsing
    var queryStr string

    fields := map[string]string{
				    "cmd": cmdStr,
			  }
    if len(queryStr) > 0 {
        fields["query"] = queryStr
    }
    p.connection.Log(cilium.EntryType_Request,
			&cilium.LogEntry_GenericL7{
				GenericL7: &cilium.L7LogEntry{
					Proto:  "mysql",
					Fields: fields,
				},
			})

    log.Infof("Logging message of cmd '%s'", cmdStr)
	return PASS, int(requestLen + mysqlHdrLen)
}

