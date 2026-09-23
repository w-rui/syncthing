// Copyright (C) 2026 The Syncthing Authors.
// SPDX-License-Identifier: MPL-2.0

// This isolated BEP peer uses an existing test device certificate to issue a
// direct block request that an ordinary Syncthing peer would not make when its
// visible index excludes the path.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/syncthing/syncthing/lib/protocol"
)

type peerModel struct {
	cluster chan struct{}
	closed  chan error
}

func (*peerModel) Index(protocol.Connection, *protocol.Index) error             { return nil }
func (*peerModel) IndexUpdate(protocol.Connection, *protocol.IndexUpdate) error { return nil }
func (*peerModel) Request(protocol.Connection, *protocol.Request) (protocol.RequestResponse, error) {
	return nil, protocol.ErrGeneric
}
func (m *peerModel) ClusterConfig(protocol.Connection, *protocol.ClusterConfig) error {
	select {
	case m.cluster <- struct{}{}:
	default:
	}
	return nil
}
func (m *peerModel) Closed(_ protocol.Connection, err error) {
	select {
	case m.closed <- err:
	default:
	}
}
func (*peerModel) DownloadProgress(protocol.Connection, *protocol.DownloadProgress) error { return nil }

type info struct{ net.Conn }

func (info) Type() string             { return "tcp-client" }
func (info) Transport() string        { return "tcp" }
func (info) IsLocal() bool            { return true }
func (info) Priority() int            { return 10 }
func (i info) String() string         { return i.Conn.RemoteAddr().String() }
func (info) Crypto() string           { return "TLS1.3" }
func (info) EstablishedAt() time.Time { return time.Now() }
func (info) ConnectionID() string     { return "domune-acl-probe" }

func run() error {
	if len(os.Args) != 8 {
		return fmt.Errorf("usage: domuneaclpeer CERT KEY ADDRESS REMOTE_ID SELF_ID PATH ALIAS_PATH")
	}
	cert, err := tls.LoadX509KeyPair(os.Args[1], os.Args[2])
	if err != nil {
		return err
	}
	remoteID, err := protocol.DeviceIDFromString(os.Args[4])
	if err != nil {
		return err
	}
	selfID, err := protocol.DeviceIDFromString(os.Args[5])
	if err != nil {
		return err
	}
	raw, err := (&net.Dialer{Timeout: 3 * time.Second}).Dial("tcp", os.Args[3])
	if err != nil {
		return err
	}
	conn := tls.Client(raw, &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true, NextProtos: []string{"bep/1.0"}, MinVersion: tls.VersionTLS13})
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		return err
	}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) != 1 || protocol.NewDeviceID(state.PeerCertificates[0].Raw) != remoteID {
		return fmt.Errorf("unexpected server identity")
	}
	if _, err := protocol.ExchangeHello(conn, protocol.Hello{ClientName: "domune-acl-probe", ClientVersion: "v1", Timestamp: time.Now().UnixNano()}); err != nil {
		return err
	}
	model := &peerModel{cluster: make(chan struct{}, 1), closed: make(chan error, 1)}
	bep := protocol.NewConnection(remoteID, conn, conn, conn, model, info{conn}, protocol.CompressionNever, protocol.NewKeyGenerator())
	bep.Start()
	defer bep.Close(errors.New("probe complete"))
	bep.ClusterConfig(&protocol.ClusterConfig{Folders: []protocol.Folder{{ID: "probe", Type: protocol.FolderTypeSendReceive, Devices: []protocol.Device{{ID: selfID}, {ID: remoteID}}}}}, nil)
	select {
	case <-model.cluster:
	case <-time.After(3 * time.Second):
		return fmt.Errorf("remote cluster config timeout")
	}
	payload := []byte("unauthorized content")
	hash := sha256.Sum256(payload)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	allowed := []byte("authorized read from a")
	allowedHash := sha256.Sum256(allowed)
	allowedData, allowedErr := bep.Request(ctx, &protocol.Request{Folder: "probe", Name: "shared/from-a.txt", Size: len(allowed), Hash: allowedHash[:]})
	data, requestErr := bep.Request(ctx, &protocol.Request{Folder: "probe", Name: os.Args[6], Size: len(payload), Hash: hash[:]})
	result := map[string]any{"connected": true, "authorizedBytes": len(allowedData), "authorizedDenied": allowedErr != nil, "authorizedContentValid": bytes.Equal(allowedData, allowed), "path": os.Args[6], "denied": requestErr != nil, "bytes": len(data)}
	if allowedErr != nil {
		result["authorizedError"] = allowedErr.Error()
	}
	if requestErr != nil {
		result["error"] = requestErr.Error()
	}
	aliasData, aliasErr := bep.Request(ctx, &protocol.Request{Folder: "probe", Name: os.Args[7], Size: len(payload), Hash: hash[:]})
	result["aliasPath"] = os.Args[7]
	result["aliasBytes"] = len(aliasData)
	result["aliasDenied"] = aliasErr != nil
	if aliasErr != nil {
		result["aliasError"] = aliasErr.Error()
	}
	if allowedErr != nil {
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	deletion := protocol.FileInfo{
		Name: "shared/from-b.txt", Type: protocol.FileInfoTypeFile, Deleted: true,
		Sequence: 1, Version: protocol.Vector{}.Update(selfID.Short()),
	}
	if err := bep.Index(ctx, &protocol.Index{Folder: "probe", Files: []protocol.FileInfo{deletion}, LastSequence: 1}); err != nil {
		return err
	}
	result["deleteSent"] = true
	select {
	case closeErr := <-model.closed:
		result["closedAfterDelete"] = true
		if closeErr != nil {
			result["closeError"] = closeErr.Error()
		}
	case <-time.After(3 * time.Second):
		result["closedAfterDelete"] = false
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
