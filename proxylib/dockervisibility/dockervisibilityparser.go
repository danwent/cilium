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

package dockervisibility

import (
	"bytes"
	"fmt"
    "io/ioutil"
	"regexp"
    "net/http"
    "encoding/json"
	"github.com/cilium/cilium/proxylib/proxylib"
    "time"
	"github.com/cilium/proxy/go/cilium/api"
	log "github.com/sirupsen/logrus"
)

//
// Docker Visibility
//
// This proxy acts as the visibility + enforcement component of a
// proof-of-concept for Cilium process level visibility + filtering.
// Note: we do not actually use the golang framework for L7 parsing in
// in this scenario.  We simply use this as a framework where we can
// queue a connection while we lookup the associated metadata for visibility
// and enforcement.
//
// Note: this parser only makes sense as an egress L7 TCP rule, since it relies
// on information extracted about local sending TCP sockets.  Implementation is v4
// specific, but adding v6 support should be simple.   Essentially, we
// use BPF to via an external agent to associated docker metadata with a
// <src IP, src port> pair.  When this proxy receives a connection, it performs
// a local lookup via a TCP connection to grab the associated docker metadata,
// and makes a forwarding decision while also logging that data to the access log.

// To start, this parser will match on 'container_name' and 'type' fields
// container_name is a regex match, type is an exact match.  Unspecified fields
// are a wildcard.
// {} - allow all, access log visibility only, allow all connections.
// {type : "run"}  - Allows connections from the pod, as long as
//                   they are the root process started in the i
//                   container by docker run.
// {container_name : "nodejs" } - Allows connections from the pod's 'nodejs' container
// {container_name " "nodejs", type "exec" }  - Allow connections from the 'nodejs'
//                                                container, but only processes spawned via
//                                                docker exec.

type dockerVisibilityRule struct {
	typeExact                  string
	containerNameRegexCompiled *regexp.Regexp
}

type dockerVisibilityRequestData struct {
	processType   string
	containerName string
}

func (rule *dockerVisibilityRule) Matches(data interface{}) bool {
	// Cast 'data' to the type we give to 'Matches()'

	reqData, ok := data.(dockerVisibilityRequestData)
	regexStr := ""
	if rule.containerNameRegexCompiled != nil {
		regexStr = rule.containerNameRegexCompiled.String()
	}

	if !ok {
		log.Warning("Matches() called with type other than dockerVisibilityRequestData")
		return false
	}
	if len(rule.typeExact) > 0 && rule.typeExact != reqData.processType {
		log.Infof("DockerVisibilityRule: type mismatch %s, %s", rule.typeExact,
			reqData.processType)
		return false
	}
	if rule.containerNameRegexCompiled != nil &&
		!rule.containerNameRegexCompiled.MatchString(reqData.containerName) {
		log.Infof("dockerVisibilityRule: container_name mismatch %s, %s",
			rule.containerNameRegexCompiled.String(), reqData.containerName)
		return false
	}
	log.Infof("policy match for rule: '%s' '%s'", rule.typeExact, regexStr)
	return true
}

// ruleParser parses protobuf L7 rules to enforcement objects
// May panic
func ruleParser(rule *cilium.PortNetworkPolicyRule) []proxylib.L7NetworkPolicyRule {
	l7Rules := rule.GetL7Rules()
	var rules []proxylib.L7NetworkPolicyRule
	if l7Rules == nil {
		return rules
	}
	for _, l7Rule := range l7Rules.GetL7Rules() {
		var rr dockerVisibilityRule
		for k, v := range l7Rule.Rule {
			switch k {
			case "type":
				rr.typeExact = v
			case "container_name":
				if v != "" {
					rr.containerNameRegexCompiled = regexp.MustCompile(v)
				}
			default:
				proxylib.ParseError(fmt.Sprintf("Unsupported key: %s", k), rule)
			}
		}
		if rr.typeExact != "" &&
			rr.typeExact != "run" &&
			rr.typeExact != "exec" {
			proxylib.ParseError(fmt.Sprintf("Unable to parse L7 docker visibility rule with invalid type: '%s'", rr.typeExact), rule)
		}
		regexStr := ""
		if rr.containerNameRegexCompiled != nil {
			regexStr = rr.containerNameRegexCompiled.String()
		}
		log.Infof("Parsed rule '%s' '%s'", rr.typeExact, regexStr)
		rules = append(rules, &rr)
	}
	return rules
}

type factory struct{}

func init() {
	log.Info("init(): Registering DockerVisibilityParserFactory")
	proxylib.RegisterParserFactory("dockervisibility", &factory{})
	proxylib.RegisterL7RuleParser("dockervisibility", ruleParser)
}

type parser struct {
	connection *proxylib.Connection
	inserted   bool
}

type dockerVisibilityInfo struct {
	Type           string `json:"type"`
	ContainerName  string `json:"container_name"`
	ContainerImage string `json:"container_image"`
	ContainerID    string `json:"container_id"`
	Entrypoint     string `json:"entrypoint"`
	Privileged     bool `json:"privileged"`
}

func (f *factory) Create(connection *proxylib.Connection) proxylib.Parser {
	log.Debugf("DockerVisibilityParserFactory: Create: %v", connection)

    // give time to gather metadata
    time.Sleep(100 * time.Millisecond)

	log.Infof("lookup docker metadata for src address: '%s'", connection.SrcAddr)
    url := "http://localhost:9999/lookup.json"
    httpClient := http.Client{
		Timeout: time.Second * 2, // Maximum of 2 secs
	}
    body_buf := bytes.NewBufferString(connection.SrcAddr)
    req, _ := http.NewRequest(http.MethodGet, url, body_buf)
	res, getErr := httpClient.Do(req)
	if getErr != nil {
		log.Fatal(getErr)
	}

	body, _ := ioutil.ReadAll(res.Body)
    log.Infof("received lookup response '%s'", body)


    dvInfo := dockerVisibilityInfo{}
	jsonErr := json.Unmarshal(body, &dvInfo)
	if jsonErr != nil {
		log.Fatal(jsonErr)
	}

	reqData := dockerVisibilityRequestData{processType: dvInfo.Type,
		containerName: dvInfo.ContainerName}

	//reqData := dockerVisibilityRequestData{processType: "run",
	//	containerName: "foo"}
	matches := true
	access_log_entry_type := cilium.EntryType_Request

	if !connection.Matches(reqData) {
		matches = false
		access_log_entry_type = cilium.EntryType_Denied
	}

	connection.Log(access_log_entry_type,
		&cilium.LogEntry_GenericL7{
			GenericL7: &cilium.L7LogEntry{
				Proto: "dockervisibility",
				Fields: map[string]string{
					"process_type":   reqData.processType,
					"container_name": reqData.containerName,
				},
			},
		})

	if !matches {
		// drop connection
		return nil
	}

	// allow connection
	return &parser{connection: connection}
}

func (p *parser) OnData(reply, endStream bool, dataArray [][]byte) (proxylib.OpType, int) {

	// inefficient, but simple
	data := string(bytes.Join(dataArray, []byte{}))

	log.Infof("OnData: '%s'", data)
    if len(data) == 0 {
		return proxylib.MORE, 1
    }

	return proxylib.PASS, len(data)
}
