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

package postgresql

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
// PostgreSQL v3 Visibility Parser
//
//  Note: this is a very basic parser, intended only for visibility
// (i.e., there is no filtering).  Currently only requests are logged
// and only high-level information about the requests are logged,
// namely, the "type" of the request, and if it is a Simple or Parsed Query
// the Query string.
//
// References on PostgreSQL protocol:
// - https://www.pgcon.org/2014/schedule/attachments/330_postgres-for-the-wire.pdf
// - https://www.postgresql.org/docs/9.3/protocol-flow.html
// - https://wiki.wireshark.org/PostgresProtocol

type PostgreSQLRule struct {
	queryActionExact   string
	tableRegexCompiled *regexp.Regexp
}

func (rule *PostgreSQLRule) Matches(data interface{}) bool {
    // no policy for now
	return true
}

// PostgresSQLRuleParser parses protobuf L7 rules to enforcement objects
// May panic
func PostgreSQLRuleParser(rule *cilium.PortNetworkPolicyRule) []L7NetworkPolicyRule {
	var rules []L7NetworkPolicyRule
	l7Rules := rule.GetL7Rules()
	if l7Rules == nil {
		return rules
	}
	return rules
}

type PostgreSQLParserFactory struct{}

var postgreSQLParserFactory *PostgreSQLParserFactory

func init() {
	log.Debug("init(): Registering postgreSQLParserFactory")
	RegisterParserFactory("postgresql", postgreSQLParserFactory)
	RegisterL7RuleParser("postgresql", PostgreSQLRuleParser)
}

type PostgreSQLParser struct {
	connection *Connection
	inserted   bool
    // tracks whether client messages are going to be
    // startup messages (no initial 'type' byte) in
    // msg format, or standard messages (initial byte
    // indicates 'type')
	startup_complete   bool
}

func (pf *PostgreSQLParserFactory) Create(connection *Connection) Parser {
	log.Debugf("PostgreSQLParserFactory: Create: %v", connection)

	p := PostgreSQLParser{connection: connection}
    p.startup_complete = false
	return &p
}

// header is 1 byte type + 4 byte length
// except for start-up message which does
// not have a type.
const pgHdrLen = 5

var typeMap = map[byte]string{
	0x01: "Startup", // not a real type
    0x42: "Bind",
    0x44: "Describe",
    0x45: "Execute",
    0x51: "Query",
    0x53: "Sync",
    0x70: "Password",
}

func (p *PostgreSQLParser) OnData(reply, endStream bool, dataArray [][]byte) (OpType, int) {

	// inefficient, but simple for now
	data := bytes.Join(dataArray, []byte{})

    log.Infof("OnData length %d, reply = %t", len(data), reply)
	hex_str := make([]byte, hex.EncodedLen(len(data)))
	hex.Encode(hex_str, data)
    log.Infof("OnData: ==> '%s'", hex_str)

    if reply {
        if len(data) == 0 {
		    return MORE, 1
        }

        if (!p.startup_complete) {
            if (data[0] != 'N' && data[0] != 'E') {
                log.Infof("received server reply of '%c', considering startup complete", data[0])
                p.startup_complete = true
                return PASS, 1
            } else {
                log.Infof("received server reply error of '%c', startup is NOT complete", data[0])
            }
        }
		return PASS, len(data)
	}

    if len(data) < pgHdrLen {
		// Partial header received, ask for more
		needs := pgHdrLen - len(data)
		log.Infof("Did not receive full header, need %d more bytes", needs)
		return MORE, needs
	}


    var requestLen uint32
    var requestType byte
    var queryStr string
	// full header available, read full request length
    if (!p.startup_complete) {
	    requestLen = binary.BigEndian.Uint32(data[0:4])
        requestType = 0x01
		log.Infof("Startup Message received")
    } else {
	    requestLen = 1 + binary.BigEndian.Uint32(data[1:5])
        requestType = data[0]
		log.Infof("Non-Startup Message received")
    }

	log.Infof("Request length = %d, Request type '%c'", requestLen, requestType)
	dataMissing := int(requestLen) - len(data)
	if dataMissing > 0 {
		// full header received, but only partial request

		log.Infof("Hdr received, but need %d more bytes of request", dataMissing)
		return MORE, dataMissing
	}

    if (requestType == 0x50) {
        // need to skip the statement name, scan until we find null
        var i uint32
        var j uint32
        for i = 6;  i<= (requestLen - 1); i++ {
            if (data[i] == 0) { break }
        }
        for j = (i+1);  j<= (requestLen - 1); j++ {
            if (data[j] == 0) { break }
        }
        queryStr = string(data[(i+1):j])
        log.Infof("Parse Query String: '%s'", queryStr)
    } else if (requestType == 0x51) {
        queryStr = string(data[5:(requestLen - 1)])
        log.Infof("Simple Query String: '%s'", queryStr)
    }

    typeStr, ok := typeMap[requestType]
    if !ok {
        typeStr = "Unknown Type Code: " + string(requestType)
    }
    fields := map[string]string{
				    "type": typeStr,
			  }
    if len(queryStr) > 0 {
        fields["query"] = queryStr
    }
    p.connection.Log(cilium.EntryType_Request,
			&cilium.LogEntry_GenericL7{
				GenericL7: &cilium.L7LogEntry{
					Proto:  "postgres",
					Fields: fields,
				},
			})

    log.Infof("Logging message of type '%s'", typeStr)
	return PASS, int(requestLen)
}

