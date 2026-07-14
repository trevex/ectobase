/* VyOS WAN edge #2 for the xdp-dp N-S egress fabric. HA peer of edge1: single-homed to sw2 (eth1,
 * unnumbered eBGP), eth2 to the clabwan host bridge. dum0 carries the SAME anycast edge underlay
 * fd00:db8:0:9::e/128 as edge1 -> the fabric ECMPs egress across both edges and either edge handles
 * any return (drain-safe, stateless). See edge1.boot for the full datapath description. */
interfaces {
    dummy dum0 {
        // UNIQUE control-plane identity for edge2 (see edge1.boot for the rationale).
        address "fd00:db8:0:9::2/128"
    }
    ethernet eth2 {
        address "172.29.0.12/24"
        address "fd00:29::12/64"
    }
    loopback lo {
    }
}
protocols {
    bgp {
        address-family {
            ipv6-unicast {
                maximum-paths {
                    ebgp "64"
                }
                network fd00:db8:0:9::2/128 {
                }
                network fd00:db8:0:9::e/128 {
                }
            }
        }
        neighbor eth1 {
            interface {
                v6only {
                    peer-group "fabric"
                }
            }
        }
        parameters {
            bestpath {
                as-path {
                    multipath-relax
                }
            }
            router-id "10.0.9.2"
        }
        peer-group fabric {
            address-family {
                ipv6-unicast {
                }
            }
            bfd {
            }
            capability {
                extended-nexthop
            }
            remote-as "external"
        }
        system-as "65009"
    }
    static {
        route 0.0.0.0/0 {
            next-hop 172.29.0.1 {
            }
        }
        route6 ::/0 {
            next-hop fd00:29::1 {
            }
        }
        // Anycast edge underlay: RIB-only (BGP announces it) without a source-eligible address.
        route6 fd00:db8:0:9::e/128 {
            blackhole {
            }
        }
    }
}
system {
    config-management {
        commit-revisions "100"
    }
    console {
        device ttyS0 {
            speed "115200"
        }
    }
    host-name "edge2"
    login {
        user vyos {
            authentication {
                encrypted-password "$6$QxPS.uk6mfo$9QBSo8u1FkH16gMyAVhus6fU3LOzvLR9Z9.82m3tiHFAxTtIkhaZSWssSgzt4v4dGAL8rhVQxTg0oAG9/q11h/"
                plaintext-password ""
            }
        }
    }
    option {
        reboot-on-upgrade-failure "5"
    }
}


// Warning: Do not remove the following line.
// vyos-config-version: "bgp@8:broadcast-relay@1:cluster@2:config-management@1:conntrack@6:conntrack-sync@2:container@3:dhcp-relay@2:dhcp-server@11:dhcpv6-server@6:dns-dynamic@4:dns-forwarding@4:firewall@20:flow-accounting@3:https@7:ids@2:interfaces@34:ipoe-server@4:ipsec@14:isis@3:l2tp@9:lldp@3:mdns@1:monitoring@2:nat@8:nat66@3:nhrp@1:ntp@3:openconnect@3:openvpn@5:ospf@2:pim@1:pki@1:policy@9:pppoe-server@12:pptp@5:qos@3:quagga@12:reverse-proxy@3:rip@1:rpki@2:snmp@3:ssh@3:sstp@6:system@33:vpp@6:vrf@4:vrrp@4:vyos-accel-ppp@2:wanloadbalance@4:webproxy@2"
// Release version: 2026.06.30-0048-rolling
