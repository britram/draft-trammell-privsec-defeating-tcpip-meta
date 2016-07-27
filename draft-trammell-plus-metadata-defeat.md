---
title: Detecting and Defeating Metadata Injection in TCP/IP
abbrev: Defeating Metadata
docname: draft-trammell-plus-metadata-defeat
date: 2016-07-29
category: info

ipr: trust200902
area: Transport
workgroup: PLUS BoF
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: B. Trammell
    name: Brian Trammell
    organization: ETH Zurich
    email: ietf@trammell.ch

normative:
  RFC6973:
  RFC6994:
  RFC7624:

informative:
  I-D.hardie-privsec-metadata-insertion:
  blind-tcp-attacks:
    target: http://www.caida.org/~mjl/pubs/blind.pdf
    title: Resilience of Deployed TCP to Blind Attacks
    author:
      - 
        name: Matthew Luckie
        ins: M. Luckie
      -
        name: Robert Beverly
        ins: R. Beverly
      - 
        name: Tiange Wu
        ins: T. Wu
      -
        name: Mark Allman
        ins: M. Allman
      -
        name: kc claffy
        ins: K. Claffy
    date: 2015

--- abstract

The TCP/IP stack provides many protocols and protocol features that can potentially be abused by on-path attackers to inject metadata about a traffic flow into that traffic flow in band. This document defines a threat model for metadata injection, catalogs protocol features that may be used to achieve it, and provides guidance for defeating this abuse, with an analysis of protocol features that are disabled by the proposed defeat mechanism.

--- middle

# Introduction

This document considers a specific threat model related to the pervasive
surveillance threat model defined in {{RFC7624}} and correlation and
identification of users as defined in sections 5.2.1 and 5.2.2, respectively,
of {{RFC6973}}. The attacker has access to the access network(s) connecting a
user to the Internet, by collaborating with, coopting, or being the user's
access provider. It can see all inbound and outbound traffic from the user via
that network, and can modify inbound and outbound packets to the user. The
attacker would like to add metadata to the user's traffic flows in order to
expose that metadata to networks the user communicates with, where it will be
passively observed, and it would like this metadata to appear in layers 3 or
4, in order to be completely transparent to the application.  For purposes of
this analysis, we presume this metadata is a user identifier or partial user
identifier.  We propose a colloquial term for this type of sub-application
identification: "hypercookie".

The attacker is variably interested in avoiding detection of hypercookie
techniques, and is variably interested in metadata reliability, but  requires
that the injected metadata not interfere with normal protocol operation, even
if the exposed metadata is not used by any far endpoint.

This document is concerned only with identification through hypercookie
injection at the transport layer, as this is possible even when the
application layer is encrypted using TLS or other encryption schemes that
operate above the transport layer. Application layer hypercookie injection is
out of scope, as are identification methods using traffic fingerprinting. It
is also concerned only with TCP as defined, not as implemented and deployed;
exploitation of other behaviors in implemented TCP stacks (e.g. as outlined in
{{blind-tcp-attacks}} may also be used for hypercookie exposure, albeit with
further risk of connection disruption.

Further, Out-of-band identification methods, e.g. linking a flow's five- or
six-tuple with an identifier and using some other protocol to export this
linkage, is also not considered, as it is practically impossible for users and
far endpoints to detect and defeat.

The metadata injection techniques presented in this document are emphatically
not recommended for use on the Internet; this document is intended to educate
members of the Internet engineering community about the potential for abuse in
TCP as defined and deployed.

# Terminology

todo

define stateless TCP firewall.

define stateful TCP firewall.

define split TCP device.

# Injection abusing Internet Protocol features

## Identification using EAP64 addressing

todo: before privacy addressing IPv6 did this automatically. mitigation: don't
use EAP64 SLAAC. what breaks: practically nothing, you should already be doing this.

## Identification using DHCPv6

todo: if attacker can run a dhcpv6 server, can place user identifying
information in the host part of the address. defeat: disable dhcpv6 on client.
what breaks: dhcpv6. detection without defeat: analyze assigned address to see
how persistently it is linked to a user.

# Injection abusing Legacy Internet Protocol features

## Fragment Identifier Rewriting

todo: does this actually work? rewrite ip id, you get sixteen bits.
mitigation: none with vanilla IPv4.

# Injection abusing Transmission Control Protocol Features

## Initial Sequence Number Rewriting

todo: initial sequence number can be rewritten for 32 bits of identification
per flow.  can use subsequent connections to the same server to leak bits
serially, with coding for error correction. requires flow state tracking to
rewrite all sequence numbers in the flow. does not work if other ISN rewriting
proxies live along the path, signal does not traverse split TCP devices.
mitigation: none with vanilla TCP. use header modification detection as in
hiccups.

## Urgent Pointer Identification

todo: urgent pointer not broken in most cases without split TCP, because it
would require a checksum recalc. need more data. you get 16 bits, but can use
subsequent connections to the same server to leak bits serially, with coding
for error correction. mitigation: configure all firewalls to zero urgent
pointer when URG flag not set. what breaks: other efforts to reuse urgent
pointer.

## Piggybacked Experimental TCP Options

todo: find a packet with enough headroom between segment and MTU, add an
experimental TCP option with metadata. you can even allocate an ExId
{{RFC6994}} and give in an innocuous name so people won't look too closely at
your traffic. option will be ignored by far endpoint. won't pass certain
middleboxes or firewalls. mitigation: aggressive deployment of stateless TCP
firewalls configured to drop all experimental options not in use on the
network. what breaks: TCP Fast Open, as some implementations still use the
experimental option; anything your stateless firewalls don't understand, such
as other TCP options and transport protocols.

## Empty Segments with Experimental TCP Options

todo: as above, but if you can't find a packet with enough headroom you can
just generate a pure ACK and stick an option on it. mitigation: as above. what
breaks: as above.

## Bad Checksum Segments

todo: send segments not generated by client with a bad checksum, place
metadata in segment. bad checksum segments will traverse any device not
looking at tcp, but will not pass any stateless or stateful TCP firewall  or
split TCP device. they will be dropped by the endpoint. mitigation: aggressive
deployment of stateless TCP firewalls will cause early drop of bad checksum
segments. what breaks: anything your stateless firewalls don't understand,
such as other TCP options and transport protocols.

## Christmas Tree Segments

todo: send segments not generated by client with silly flag combinations,
place metadata in segment. out of window segments will traverse any device not
looking at TCP, but will not pass any properly configured stateless or
stateful TCP firewall or split TCP device. careless selection of flags may
lead to state breakage, so this method is brittle compared to the other ones.
mitigation: aggressive deployment of stateless TCP firewalls will cause early
drop of christmas tree segments.

# Recommendations

todo: bad news: users can't do anything to mitigate. can detect if they test
against their own far endpoints. altruistic mitigation: tcp-checking firewalls
everywhere. downside:

# IANA Considerations

This document has no actions for IANA [EDITOR'S NOTE: please remove this section at publication.]

# Security Considerations

# Acknowledgments

mami ack. plus bof participants ack.
