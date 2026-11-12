module github.com/Zuplu/postfix-tlspol

go 1.27.4

godebug multipathtcp=0

require (
	codeberg.org/miekg/dns v0.6.132
	go.yaml.in/yaml/v4 v4.0.0
	golang.org/x/sync v0.25.0
	golang.org/x/sys v0.50.0
)

require (
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.62.0 // indirect
)
