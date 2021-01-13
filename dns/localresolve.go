package dns

import (
	"context"
	"net"

	D "github.com/miekg/dns"
)

type localResolveClient struct {
}

func (lrc *localResolveClient) Exchange(m *D.Msg) (msg *D.Msg, err error) {
	return lrc.ExchangeContext(context.Background(), m)
}

func (lrc *localResolveClient) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	q := &m.Question[0]

	var ipAddr *net.IPAddr
	answers := []D.RR{}
	if q.Qtype == D.TypeA {
		ipAddr, err = net.ResolveIPAddr("ip4", q.Name)
	} else if q.Qtype == D.TypeAAAA {
		ipAddr, err = net.ResolveIPAddr("ip6", q.Name)
	}


	if err == nil {
		if q.Qtype == D.TypeA {
			var answer D.RR
			answer = &D.A {
				Hdr: D.RR_Header{
					Name: q.Name,
					Rrtype: D.TypeA,
					Class: D.ClassINET,
					Ttl: 120,
					Rdlength: 4,
				},
				A: ipAddr.IP,
			}
			answers = append(answers, answer)
		} else if q.Qtype == D.TypeAAAA {
			var answer D.RR
			answer = &D.AAAA {
				Hdr: D.RR_Header{
					Name: q.Name,
					Rrtype: D.TypeAAAA,
					Class: D.ClassINET,
					Ttl: 120,
					Rdlength: 16,
				},
				AAAA: ipAddr.IP,
			}
			answers = append(answers, answer)
		}
	}


	msg = &D.Msg{
		MsgHdr: D.MsgHdr{
			Id: m.MsgHdr.Id,
			Response: true,
			Opcode: 0,
			Authoritative: false,
			Truncated: false,
			RecursionDesired: true,
			RecursionAvailable: true,
			Zero: true,
			AuthenticatedData: false,
			CheckingDisabled: false,
			Rcode: 0,
		},

		Question: []D.Question {
			*q,
		},

		Answer: answers,
	}

	return msg, err
}
