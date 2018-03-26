// Copyright 2017-2018 Authors of Cilium
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

package proxy

import (
	"encoding/json"
	"fmt"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/identity"
	"io"
	"time"
	"unicode"
	//	"github.com/cilium/cilium/pkg/kafka"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	// "github.com/cilium/cilium/pkg/proxy/accesslog"
	// "github.com/cilium/cilium/pkg/proxy/logger"

	"github.com/sirupsen/logrus"
)

//const (
//	fieldID = "id"
//)

// bmcRedirect implements the Redirect interface for an l7 proxy
type bmcRedirect struct {
	redirect *Redirect
	conf     bmcConfiguration
	rules    policy.L7DataMap
	socket   *proxySocket
}

//type destLookupFunc func(remoteAddr string, dport uint16) (uint32, string, error)

type bmcConfiguration struct {
	noMarker      bool
	lookupNewDest destLookupFunc
}

// createBmcRedirect creates a redirect to the binary memcache proxy. The redirect structure passed
// in is safe to access for reading and writing.
func createBmcRedirect(r *Redirect, conf bmcConfiguration) (RedirectImplementation, error) {
	redir := &bmcRedirect{
		redirect: r,
		conf:     conf,
	}

	if redir.conf.lookupNewDest == nil {
		redir.conf.lookupNewDest = lookupNewDest
	}

	marker := 0
	if !conf.noMarker {
		markIdentity := int(0)
		// As ingress proxy, all replies to incoming requests must have the
		// identity of the endpoint we are proxying for
		if r.ingress {
			markIdentity = int(r.source.GetIdentity())
		}

		marker = GetMagicMark(r.ingress, markIdentity)
	}

	// Listen needs to be in the synchronous part of this function to ensure that
	// the proxy port is never refusing connections.
	socket, err := listenSocket(fmt.Sprintf(":%d", r.ProxyPort), marker)
	if err != nil {
		return nil, err
	}

	redir.socket = socket

	go func() {
		for {
			pair, err := socket.Accept(true)
			select {
			case <-socket.closing:
				// Don't report errors while the socket is being closed
				return
			default:
			}

			if err != nil {
				log.WithField(logfields.Port, r.ProxyPort).WithError(err).Error("Unable to accept connection on port")
				continue
			}

			go redir.handleRequestConnection(pair)
		}
	}()

	return redir, nil
}

// canAccess determines if the memcache req sent by identity is allowed to
// be forwarded according to the rules configured on binaryMemcacheRedirect
func (bmc bmcRedirect) canAccess(opCode byte, srcIdentity identity.NumericIdentity) bool {
	var id *identity.Identity

	if srcIdentity != 0 {
		id = identity.LookupIdentityByID(srcIdentity)
		if id == nil {
			log.WithFields(logrus.Fields{
				logfields.Identity: srcIdentity,
			}).Warn("Unable to resolve identity to labels")
		}
	}

	scopedLog := log.WithFields(logrus.Fields{
		logfields.Identity: id,
	})

	bmc.redirect.mutex.RLock()
	rules := bmc.redirect.rules.GetRelevantRules(id)
	bmc.redirect.mutex.RUnlock()

	if rules.BinaryMemcache == nil {
		flowdebug.Log(scopedLog, "No Memcache rules matching identity, rejecting")
		return false
	}

	b, err := json.Marshal(rules.BinaryMemcache)
	if err != nil {
		flowdebug.Log(scopedLog, "Error marshalling memcache rules to apply")
		return false
	} else {
		flowdebug.Log(scopedLog.WithField("rule", string(b)), "Applying rule")
	}

	for _, rule := range rules.BinaryMemcache {
		if opCode == api.MemcacheOpCodeMap[rule.OpCode] {
			return true
		}
	}

	return false
}

func (bmc *bmcRedirect) handleRequest(pair *connectionPair, buf []byte) {

	scopedLog := log.WithField(fieldID, pair.String())
	flowdebug.Log(scopedLog.WithField(logfields.Request, string(buf)), "Handling binary Memcache request")

	addr := pair.Rx.conn.RemoteAddr()
	if addr == nil {
		info := fmt.Sprint("RemoteAddr() is nil")
		scopedLog.Warn(info)
		return
	}

	// retrieve identity of source together with original destination IP
	// and destination port
	srcIdentity, dstIPPort, err := bmc.conf.lookupNewDest(addr.String(), bmc.redirect.ProxyPort)
	if err != nil {
		scopedLog.WithField("source",
			addr.String()).WithError(err).Error("Unable lookup original destination")
		return
	}

	if pair.Tx.Closed() {
		marker := 0
		if !bmc.conf.noMarker {
			marker = GetMagicMark(bmc.redirect.ingress, int(srcIdentity))
		}

		flowdebug.Log(scopedLog.WithFields(logrus.Fields{
			"marker":      marker,
			"destination": dstIPPort,
		}), "Dialing original destination")

		txConn, err := ciliumDialer(marker, addr.Network(), dstIPPort)
		if err != nil {
			scopedLog.WithError(err).WithFields(logrus.Fields{
				"origNetwork": addr.Network(),
				"origDest":    dstIPPort,
			}).Error("Unable to dial original destination")

			return
		}

		pair.Tx.SetConnection(txConn)

		// Start go routine to handle responses and pass in a copy of
		go bmc.handleResponseConnection(pair)
	}

	op_code := buf[1]
	if !bmc.canAccess(op_code, identity.NumericIdentity(srcIdentity)) {
		flowdebug.Log(scopedLog, "Memcache request is denied by policy")

		// Send a 0x0024 'No Access' error
		var error_hdr = []byte{
			0x81, 0, 0, 0,
			0, 0, 0, 0x24,
			0, 0, 0, 0x0d,
			0, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 0,
			'a', 'c', 'c',
			'e', 's', 's',
			' ', 'd', 'e',
			'n', 'i', 'e',
			'd'}
		pair.Rx.Enqueue(error_hdr)
		return
	}

	flowdebug.Log(scopedLog, "Forwarding binary Memcache request")

	// Write the entire raw request onto the outgoing connection

	pair.Tx.Enqueue(buf)
}

type bmcReqMessageHandler func(pair *connectionPair, buf []byte)

func mcPrintData(buf []byte, n int) {
	for i := 0; i < n; i++ {
		if unicode.IsLetter(int32(buf[i])) {
			fmt.Printf("%c, ", buf[i])
		} else {
			fmt.Printf("%d, ", buf[i])
		}
		if i%4 == 3 {
			fmt.Printf("\n")
		}
	}
	fmt.Printf("\n")
}

func (bmc *bmcRedirect) handleRequests(done <-chan struct{}, pair *connectionPair, c *proxyConnection,
	handler bmcReqMessageHandler) {
	defer c.Close()

	scopedLog := log.WithField(fieldID, pair.String())

	hdr := make([]byte, 24)
	for {
		n, err := io.ReadFull(c.conn, hdr)

		fmt.Printf("Read %d bytes of BMC header\n", n)
		// Ignore any error if the listen socket has been closed, i.e. the
		// port redirect has been removed.
		select {
		case <-done:
			scopedLog.Debug("Redirect removed; closing Binary Memcache request connection")
			return
		default:
		}

		if err != nil {
			if err != io.EOF {
				scopedLog.WithError(err).Error("Unable to read Binary Memcache request header; closing request connection")
			}
			return
		}

		mcPrintData(hdr, n)

		if hdr[0] != 0x80 {
			scopedLog.Error(fmt.Sprint("Invalid request magic byte '%x', expected 0x80.  Cannot parse as Binary Memcache", hdr[0]))
			return
		}
		additional_len := int32(uint32(hdr[11]) | uint32(hdr[10])<<8 | uint32(hdr[9])<<16 | uint32(hdr[8])<<24)
		fmt.Printf("Received BMC header with body length of %d bytes\n", additional_len)

		body := make([]byte, additional_len)
		n, err = io.ReadFull(c.conn, body)

		// I think we need to do this each time we read, as we may block?
		select {
		case <-done:
			scopedLog.Debug("Redirect removed; closing Binary Memcache request connection")
			return
		default:
		}

		if err != nil {
			scopedLog.WithError(err).Error("Unable to read Binary Memcache request body; closing request connection")
			return
		}

		fmt.Printf("Read %d request body bytes\n", n)
		mcPrintData(body, n)

		handler(pair, append(hdr, body[:n]...))
	}
}

func (bmc *bmcRedirect) handleResponses(done <-chan struct{}, pair *connectionPair, c *proxyConnection) {
	defer c.Close()
	scopedLog := log.WithField(fieldID, pair.String())

	// FIXME: there's a bug when this buffer size is small and responses are split across buffers
	// We see this when someone runs the "stats" command.
	b := make([]byte, 204800)
	for {
		// read the raw bytes, don't bother to parse
		// c.conn is a io.Reader
		n, err := c.conn.Read(b)

		if err != nil {
			scopedLog.WithError(err).Error("Unable to read Binary Memcache response.  closing response connection")
			return
		}

		// Ignore any error if the listen socket has been closed, i.e. the
		// port redirect has been removed.
		select {
		case <-done:
			scopedLog.Debug("Redirect removed; closing binaryMemcache response connection")
			return
		default:
		}

		/*
			fmt.Printf("Read %d response bytes\n", n)
			mcPrintData(b, n)
		*/

		pair.Rx.Enqueue(b[:n])
	}
}

func (bmc *bmcRedirect) handleRequestConnection(pair *connectionPair) {
	flowdebug.Log(log.WithFields(logrus.Fields{
		"from": pair.Rx,
		"to":   pair.Tx,
	}), "Proxying request binary Memcache connection")

	bmc.handleRequests(bmc.socket.closing, pair, pair.Rx, bmc.handleRequest)

	// The proxymap contains an entry with metadata for the receive side of the
	// connection, remove it after the connection has been closed.
	if pair.Rx != nil {
		// We are running in our own go routine here so we can just
		// block this go routine until after the connection is
		// guaranteed to have been closed
		time.Sleep(proxyConnectionCloseTimeout + time.Second)

		if err := bmc.redirect.removeProxyMapEntryOnClose(pair.Rx.conn); err != nil {
			log.WithError(err).Warning("Unable to remove proxymap entry after closing connection")
		}
	}
}

func (bmc *bmcRedirect) handleResponseConnection(pair *connectionPair) {
	flowdebug.Log(log.WithFields(logrus.Fields{
		"from": pair.Tx,
		"to":   pair.Rx,
	}), "Proxying response binary Memcache connection")

	bmc.handleResponses(bmc.socket.closing, pair, pair.Tx)
}

// UpdateRules replaces old l7 rules of a redirect with new ones.
func (bmc *bmcRedirect) UpdateRules(wg *completion.WaitGroup) error {
	return nil
}

// Close the redirect.
func (bmc *bmcRedirect) Close(wg *completion.WaitGroup) {
	bmc.socket.Close()
}

func init() {
}
