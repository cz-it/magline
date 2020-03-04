// Copyright CZ. All rights reserved.
// Author: CZ cz.theng@gmail.com
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file

package magline

// Options is config option for magline
type Options struct {
	Host string `json:"host" toml:"host"`
	Port uint32 `json:"port" toml:"port"`
}

// NewOptions return a default Options
func NewOptions() *Options {
	opts := &Options{
		Host: "localhost",
		Port: 9757,
	}
	return opts
}

// Load load options from a toml  or json file
func (opts *Options) Load(fpath string) (err error) {

	return nil
}
