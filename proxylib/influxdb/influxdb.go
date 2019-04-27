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

package influxdb

import (
	"bytes"
	"fmt"
	. "github.com/cilium/cilium/proxylib/proxylib"
	"github.com/cilium/proxy/go/cilium/api"
	log "github.com/sirupsen/logrus"
	"net/http"
	"regexp"
	"strings"
)

//
// InfluxDB HTTP Parser
//
// Spec:  https://docs.influxdata.com/influxdb/v1.7/tools/api/
//

// Current InfluxDB parser supports matching on high-level action (read, write, admin, debug, all) and 'db'.
// 'db' can be a regular expression, or if not specified, is a wildcard.
// 'db' value is only valid for read, write, and all actions.
// Note: "Select into" queries require 'admin' role.
//
// Examples:
// action = 'read', db = 'db1'  // read-only acccess to db1
// action = 'all'     // everything allowed on any db (visibility only)
// db = 'db1'  // read and write allowed on db1
// action = 'debug'  // access to /debug/* URLs.

type InfluxDBRule struct {
	actionExact     string
	dbRegexCompiled *regexp.Regexp
}

type InfluxDBRequestData struct {
	action string
	db     string
}

func (rule *InfluxDBRule) Matches(data interface{}) bool {
	// Cast 'data' to the type we give to 'Matches()'

	reqData, ok := data.(InfluxDBRequestData)
	if !ok {
		log.Warning("Matches() called with type other than string")
		return false
	}
	log.Infof("Match Request: action '%s' db '%s'", reqData.action, reqData.db)
	regexStr := ""
	if rule.dbRegexCompiled != nil {
		regexStr = rule.dbRegexCompiled.String()
	}
	log.Infof("Match Rule: action '%s', db '%s'", rule.actionExact, regexStr)

	if rule.actionExact != "" && rule.actionExact != "all" &&
		reqData.action != "ping" && rule.actionExact != reqData.action {

		log.Debugf("InfluxDBRule: action mismatch %v, %s", rule.actionExact, reqData.action)
		return false
	}

	if rule.dbRegexCompiled != nil &&
		(reqData.action != "read" && reqData.action != "write") {
		log.Debugf("InfluxDBRule: InfluxDBRule:  db regex cannot match non read/write request %v, %s",
			regexStr, reqData.action)
		return false
	}

	if len(reqData.db) > 0 &&
		rule.dbRegexCompiled != nil &&
		!rule.dbRegexCompiled.MatchString(reqData.db) {
		log.Debugf("InfluxDBRule: db_regex mismatch '%s', '%s'", regexStr, reqData.db)
		return false
	}

	return true
}

// InfluxDBRuleParser parses protobuf L7 rules to enforcement objects
// May panic
func InfluxDBRuleParser(rule *cilium.PortNetworkPolicyRule) []L7NetworkPolicyRule {
	var rules []L7NetworkPolicyRule
	l7Rules := rule.GetL7Rules()
	if l7Rules == nil {
		return rules
	}
	for _, l7Rule := range l7Rules.GetL7Rules() {
		var r InfluxDBRule
		for k, v := range l7Rule.Rule {
			switch k {
			case "action":
				r.actionExact = v
			case "db":
				if v != "" {
					r.dbRegexCompiled = regexp.MustCompile(v)
				}
			default:
				ParseError(fmt.Sprintf("Unsupported key: %s", k), rule)
			}
		}
		if len(r.actionExact) > 0 {
			// ensure this is a valid query action
			res := InfluxDBActionMap[r.actionExact]
			if res == invalidAction {
				ParseError(fmt.Sprintf("Unable to parse L7 InfluxDB rule with invalid action: '%s'", r.actionExact), rule)
			} else if res == actionNoDB && r.dbRegexCompiled != nil {
				ParseError(fmt.Sprintf("L7 InfluxDB rule action '%s' is not compatible with a table match", r.actionExact), rule)
			}

		}

		log.Debugf("Parsed InfluxDBRule pair: %v", r)
		rules = append(rules, &r)
	}
	return rules
}

type InfluxDBParserFactory struct{}

var influxDBParserFactory *InfluxDBParserFactory

func init() {
	log.Info("init(): Registering InfluxDBParserFactory")
	RegisterParserFactory("influxdb", influxDBParserFactory)
	RegisterL7RuleParser("influxdb", InfluxDBRuleParser)
}

type InfluxDBParser struct {
	connection *Connection
	inserted   bool
}

func (pf *InfluxDBParserFactory) Create(connection *Connection) Parser {
	log.Debugf("InfluxDBParserFactory: Create: %v", connection)

	p := InfluxDBParser{connection: connection}
	return &p
}

// influxdb server returns a 401 unauthorized but not a 403 access denied, so
// return a 401 to maximize the chance that we don't confuse influxdb clients.
var InfluxDBAccessDeniedStr string = "HTTP/1.1 402 Access Denied\r\n" +
	"Content-Length: 76\r\n" +
	"\r\n" +
	`{"error":"authorization failed.   Request denied by Cilium Network Policy."}`

func (p *InfluxDBParser) OnData(reply, endStream bool, dataArray [][]byte) (OpType, int) {

	// inefficient, but simple for now
	data := bytes.Join(dataArray, []byte{})

	log.Infof("OnData for InfluxDB parser with %d bytes, reply %v", len(data), reply)

	if reply {
		// do not parse replies
		// FIXME: will not work with pipelining
		//        Need to parse responses, ensure we pass a full
		//        Response at a time, otherwise we risk injecting our
		//        401 failure responses "in the middle" of another reply.
		if len(data) > 0 {
			log.Infof("passing full reply of size %d", len(data))
			return PASS, len(data)
		} else {
			log.Infof("Reply with zero bytes of data")
			return MORE, 1
		}
	}

	req, reqLen, needs := parseHTTPRequest(data)
	if req == nil {
		if needs < 0 {
			log.Infof("Nil request: error")
			return ERROR, int(ERROR_INVALID_FRAME_LENGTH)
		} else {
			log.Infof("Nil request: needs more")
			return MORE, needs
		}
	}
	log.Infof("Have full request with content-length: %d", req.ContentLength)

	db := req.FormValue("db")

	action := "admin" // default to admin unless we can identify that req
	// is more benign

	if strings.HasPrefix(req.URL.Path, "/write") {
		action = "write"
	} else if strings.HasPrefix(req.URL.Path, "/query") {
		if req.Method == http.MethodGet {
			// This is a standard SELECT or SHOW
			action = "read"
		} else {
			// per-spec, query calls that create/modify
			// at the table level happen via POST.
			// This includes "SELECT INTO"
			action = "admin"
		}
	} else if strings.HasPrefix(req.URL.Path, "/debug") {
		action = "debug"
	} else if strings.HasPrefix(req.URL.Path, "/ping") {
		action = "ping" // is allowed if any other request is allowed
	}

	log.Infof("action: %s  db: %s", action, db)

	reqData := InfluxDBRequestData{action: action, db: db}

	matches := true
	access_log_entry_type := cilium.EntryType_Request

	if !p.connection.Matches(reqData) {
		matches = false
		access_log_entry_type = cilium.EntryType_Denied
	}

	p.connection.Log(access_log_entry_type,
		&cilium.LogEntry_GenericL7{
			&cilium.L7LogEntry{
				Proto: "InfluxDB",
				Fields: map[string]string{
					"action": reqData.action,
					"db":     reqData.db,
				},
			},
		})

	if !matches {
		p.connection.Inject(true, []byte(InfluxDBAccessDeniedStr))
		return DROP, reqLen
	}
	return PASS, reqLen
}

// map to test whether a 'action' is valid or not
// and whether it is compatible with an associated table

const invalidAction = 0
const actionWithDB = 1
const actionNoDB = 3
const actionEither = 4

var InfluxDBActionMap = map[string]int{
	"read":  actionWithDB,
	"write": actionWithDB,
	"debug": actionNoDB,
	"all":   actionEither,
}
