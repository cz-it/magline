// Copyright CZ. All rights reserved.
// Author: CZ cz.theng@gmail.com
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file

package magline

import (
	"time"
)

// Server is a magline TCP server
type Server struct {
}

// NewServer create a magline's TCP server
func NewServer() (svr *Server) {
	svr = &Server{}
	return svr
}

func (svr *Server) Run() {
	for {
		time.Sleep(1 * time.Second)
	}
}
