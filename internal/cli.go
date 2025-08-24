/*
 * MIT License
 * Copyright (c) 2024-2025 Zuplu
 */

package tlspol

import (
	"bufio"
	"encoding/json"
	"flag"
	"github.com/Zuplu/postfix-tlspol/internal/utils/log"
	"github.com/Zuplu/postfix-tlspol/internal/utils/netstring"
	"github.com/Zuplu/postfix-tlspol/internal/utils/valid"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
)

func flagCliConnFunc(f *flag.Flag) {
	var value string
	switch (*f).Name {
	case "query":
		cliConnMode = true
		value = (*f).Value.String()
		if len(value) == 0 || !valid.IsDNSName(value) {
			log.Errorf("Invalid domain: %q", value)
			return
		}
	case "dump", "export", "purge":
		cliConnMode = true
	default:
		return
	}
	var conn net.Conn
	var err error
	if strings.HasPrefix(config.Server.Address, "unix:") {
		conn, err = net.Dial("unix", config.Server.Address[5:])
	} else {
		conn, err = net.Dial("tcp", config.Server.Address)
	}
	if err != nil {
		log.Errorf("Could not connect to socketmap instance. Is postfix-tlspol running? (%v)", err)
		return
	}
	defer conn.Close()
	switch (*f).Name {
	case "query":
		cliQuery(f, &conn, &value)
	case "dump":
		cliDump(f, &conn, false)
	case "export":
		cliDump(f, &conn, true)
	case "purge":
		cliPurge(f, &conn)
	}
}

func cliQuery(f *flag.Flag, conn *net.Conn, value *string) {
	(*conn).Write(netstring.Marshal("JSON " + *value))
	raw, err := bufio.NewReader(*conn).ReadBytes('\n')
	if err != nil {
		log.Errorf("Could not query domain %q. (%v)", *value, err)
		return
	}
	result := new(Result)
	err = json.Unmarshal(raw, &result)
	if err != nil {
		log.Errorf("Could not query domain %q. (%v)", *value, err)
		return
	}
	o, err := os.Stdout.Stat()
	if err == nil && o.Mode()&os.ModeCharDevice != 0 {
		var buf io.WriteCloser
		if _, err := exec.LookPath("jq"); err == nil {
			jq := exec.Command("jq")
			buf, _ = jq.StdinPipe()
			jq.Stdout = os.Stdout
			jq.Stderr = os.Stderr
			defer jq.Run()
		} else {
			buf = os.Stdout
		}
		enc := json.NewEncoder(buf)
		enc.SetIndent("", "  ")
		err = enc.Encode(result)
		defer buf.Close()
	} else {
		enc := json.NewEncoder(os.Stdout)
		err = enc.Encode(result)
	}
	if err != nil {
		log.Errorf("Could not query domain %q. (%v)", *value, err)
		return
	}
	return
}

func cliDump(f *flag.Flag, conn *net.Conn, export bool) {
	if export {
		(*conn).Write(netstring.Marshal("EXPORT"))
	} else {
		(*conn).Write(netstring.Marshal("DUMP"))
		o, err := os.Stdout.Stat()
		if err == nil && o.Mode()&os.ModeCharDevice != 0 {
			if _, err := exec.LookPath("less"); err == nil {
				less := exec.Command("less")
				less.Env = append(os.Environ(), "LESS=-S --use-color --prompt=postfix-tlspol\\ in-memory\\ cache")
				less.Stdin = *conn
				less.Stdout = os.Stdout
				less.Stderr = os.Stderr
				less.Run()
				return
			}
		}
	}
	io.Copy(os.Stdout, *conn)
}

func cliPurge(f *flag.Flag, conn *net.Conn) {
	(*conn).Write(netstring.Marshal("PURGE"))
	io.Copy(os.Stdout, *conn)
}
