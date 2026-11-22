#!/usr/bin/perl
# SPDX-License-Identifier: MIT
# M08-T04 guest probe: sends the plan's UDP datagrams and TCP connection attempts, then writes what it did as JSON.
# Run only by m08-actions.sh (guarded) inside the lab guest: excl-probe.pl PLAN.json RESULT.json
# Every socket carries IP TTL 1 (the plan may not raise it): a datagram that leaves en0 dies at the vmnet gateway
# (192.168.64.1), so nothing a probe sends travels past the host, and the plan's destinations are TEST-NET or lab
# addresses only (the driver refuses others). The wire is judged from captures, not from this record.
# M08-T16 modes (px-spike.py): "flow" sends count datagrams on one socket, gap seconds apart (TTL 1, lab ranges only);
# "tcp-echo" (one TCP handshake and an HTTP HEAD) and "stun" (one RFC 5389 binding request) go to a public literal the
# plan lists in "public" (at most four) with the system TTL: the round trip the spike must prove. Their records keep the
# local address and the response status only; a STUN reply's mapped address is never written (the mapped port is).
use strict;
use warnings;
use Errno ();
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);
use JSON::PP ();
use Socket qw(AF_INET PF_INET SOCK_DGRAM SOCK_STREAM SOL_SOCKET SO_REUSEADDR inet_aton inet_ntoa pack_sockaddr_in unpack_sockaddr_in);
use Time::HiRes qw(time sleep);

my ($plan_path, $result_path) = @ARGV;
die "usage: excl-probe.pl PLAN RESULT\n" unless defined $result_path && @ARGV == 2;
# Darwin <netinet/in.h>: IPPROTO_IP 0, IP_TTL 4, IP_BOUND_IF 25; <sys/socket.h>: SO_REUSEPORT 0x200.
use constant { IPPROTO_IP => 0, IP_TTL => 4, IP_BOUND_IF => 25, SO_REUSEPORT => 0x200 };
my %ALLOWED = map { $_ => 1 } qw(198.51.100 203.0.113 192.0.2 10.77.0 192.168.64);

open my $in, '<', $plan_path or die "plan unreadable\n";
my $plan = JSON::PP::decode_json(do { local $/; <$in> });
close $in;
my $ttl = $plan->{ttl} // 1;
die "ttl must be 1\n" unless $ttl == 1;
my @public = @{ $plan->{public} // [] };
die "at most four public literals\n" if @public > 4;
for my $literal (@public) {
    die "public literal refused\n" unless $literal =~ /^(\d{1,3})\.\d{1,3}\.\d{1,3}\.\d{1,3}$/ && $1 > 0 && $1 < 224;
}
my %PUBLIC = map { $_ => 1 } @public;

sub errname {
    my ($code) = @_;
    local $! = $code;
    for my $name (sort keys %!) {
        return $name if $!{$name};
    }
    return "E$code";
}

sub en0 {
    my $text = `/sbin/ifconfig -v en0 2>/dev/null` // '';
    my ($address) = $text =~ /^\s+inet (\d+\.\d+\.\d+\.\d+) /m;
    my ($index) = $text =~ /\bindex (\d+)\b/;
    return { address => $address, index => defined $index ? $index + 0 : undef };
}

my $en0 = en0();
my %results;
my @order;

sub record {
    my ($id, $key) = @_;
    $results{$id}{$key}++;
}

sub send_probe {
    my ($probe) = @_;
    my $id = $probe->{id};
    push @order, $id unless exists $results{$id};
    $results{$id} //= { attempts => 0 };
    my $mode = $probe->{mode} // 'probe';
    if ($mode eq 'tcp-echo' || $mode eq 'stun') {
        if (!$PUBLIC{ $probe->{dst} }) {
            $results{$id}{skipped} = 'round-trip destination not listed in the plan';
            return;
        }
        return round_trip($probe, $mode);
    }
    my ($prefix) = $probe->{dst} =~ /^(\d+\.\d+\.\d+)\.\d+$/;
    if (!defined $prefix || !$ALLOWED{$prefix}) {
        $results{$id}{skipped} = 'destination outside the lab and TEST-NET ranges';
        return;
    }
    if ($mode eq 'flow' && $probe->{proto} ne 'udp') {
        $results{$id}{skipped} = 'flow mode is UDP only';
        return;
    }
    my $tcp = $probe->{proto} eq 'tcp';
    my $local = $probe->{src} || '0.0.0.0';
    if ($probe->{bind}) {
        if (!defined $en0->{index}) {
            $results{$id}{skipped} = 'en0 interface index unreadable';
            return;
        }
        $local = $en0->{address} if !$probe->{src};
        if (!defined $local) {
            $results{$id}{skipped} = 'en0 address unreadable';
            return;
        }
    }
    my $socket;
    if (!socket($socket, PF_INET, $tcp ? SOCK_STREAM : SOCK_DGRAM, $tcp ? 6 : 17)) {
        record($id, 'socket:' . errname($! + 0));
        return;
    }
    setsockopt($socket, SOL_SOCKET, SO_REUSEADDR, pack('i', 1));
    setsockopt($socket, SOL_SOCKET, SO_REUSEPORT, pack('i', 1));
    setsockopt($socket, IPPROTO_IP, IP_TTL, pack('i', $ttl)) or do { record($id, 'ttl:' . errname($! + 0)); close $socket; return };
    if ($probe->{bind}) {
        setsockopt($socket, IPPROTO_IP, IP_BOUND_IF, pack('i', $en0->{index})) or do { record($id, 'boundIf:' . errname($! + 0)); close $socket; return };
    }
    if (!bind($socket, pack_sockaddr_in($probe->{sport} // 0, inet_aton($local)))) {
        record($id, 'bind:' . errname($! + 0));
        close $socket;
        return;
    }
    my $target = pack_sockaddr_in($probe->{dport}, inet_aton($probe->{dst}));
    $results{$id}{attempts}++;
    if ($tcp) {
        my $flags = fcntl($socket, F_GETFL, 0);
        fcntl($socket, F_SETFL, $flags | O_NONBLOCK);
        if (connect($socket, $target)) {
            record($id, 'connected');
        } elsif ($! == Errno::EINPROGRESS()) {
            my $write = '';
            vec($write, fileno($socket), 1) = 1;
            my $ready = select(undef, $write, undef, 1.0);
            if ($ready > 0) {
                my $error = unpack('i', getsockopt($socket, SOL_SOCKET, 0x1007) // pack('i', 0));    # SO_ERROR
                record($id, $error ? 'connect:' . errname($error) : 'connected');
            } else {
                record($id, 'pending');
            }
        } else {
            record($id, 'connect:' . errname($! + 0));
        }
    } elsif ($mode eq 'flow') {
        # One socket, several datagrams: the later packets of one flow (spike check k).
        my $gap = $probe->{gap} // 1;
        $gap = 2 if $gap > 2;
        for my $n (1 .. ($probe->{sends} // 5)) {
            sleep($gap) if $n > 1;
            if (defined send($socket, "WGEXM08 $id $n", 0, $target)) {
                record($id, 'sent');
            } else {
                record($id, 'send:' . errname($! + 0));
            }
        }
    } else {
        my $payload = "WGEXM08 $id";
        if (defined send($socket, $payload, 0, $target)) {
            record($id, 'sent');
        } else {
            record($id, 'send:' . errname($! + 0));
        }
    }
    close $socket;
}

sub local_address {
    my ($socket) = @_;
    my $name = getsockname($socket) or return undef;
    my ($port, $address) = unpack_sockaddr_in($name);
    return inet_ntoa($address) . ":$port";
}

sub wait_readable {
    my ($socket, $seconds) = @_;
    my $read = '';
    vec($read, fileno($socket), 1) = 1;
    return select($read, undef, undef, $seconds) > 0;
}

# tcp-echo and stun: the system TTL, an unbound socket on the plan's source port, one bounded exchange.
sub round_trip {
    my ($probe, $mode) = @_;
    my $id = $probe->{id};
    my $tcp = $mode eq 'tcp-echo';
    my $socket;
    if (!socket($socket, PF_INET, $tcp ? SOCK_STREAM : SOCK_DGRAM, $tcp ? 6 : 17)) {
        record($id, 'socket:' . errname($! + 0));
        return;
    }
    setsockopt($socket, SOL_SOCKET, SO_REUSEADDR, pack('i', 1));
    setsockopt($socket, SOL_SOCKET, SO_REUSEPORT, pack('i', 1));
    if (!bind($socket, pack_sockaddr_in($probe->{sport} // 0, inet_aton('0.0.0.0')))) {
        record($id, 'bind:' . errname($! + 0));
        close $socket;
        return;
    }
    my $target = pack_sockaddr_in($probe->{dport}, inet_aton($probe->{dst}));
    $results{$id}{attempts}++;
    if ($tcp) {
        my $flags = fcntl($socket, F_GETFL, 0);
        fcntl($socket, F_SETFL, $flags | O_NONBLOCK);
        my $ok = connect($socket, $target);
        if (!$ok && $! == Errno::EINPROGRESS()) {
            my $write = '';
            vec($write, fileno($socket), 1) = 1;
            if (select(undef, $write, undef, 5.0) > 0) {
                my $error = unpack('i', getsockopt($socket, SOL_SOCKET, 0x1007) // pack('i', 0));    # SO_ERROR
                $ok = !$error;
                record($id, 'connect:' . errname($error)) if $error;
            } else {
                record($id, 'pending');
            }
        } elsif (!$ok) {
            record($id, 'connect:' . errname($! + 0));
        }
        if ($ok) {
            record($id, 'connected');
            $results{$id}{local} = local_address($socket);
            fcntl($socket, F_SETFL, $flags);
            send($socket, "HEAD / HTTP/1.0\r\nHost: $probe->{dst}\r\nConnection: close\r\n\r\n", 0);
            my $reply = '';
            if (wait_readable($socket, 5.0)) {
                sysread($socket, $reply, 512);
            }
            if ($reply =~ m{^(HTTP/\d\.\d \d{3})}) {
                record($id, 'response');
                $results{$id}{status} = $1;
            } else {
                record($id, 'noResponse');
            }
            $results{$id}{bytes} = length $reply;
        }
    } else {
        my $txid = join '', map { chr(int(rand(256))) } 1 .. 12;
        my $request = pack('nnN', 0x0001, 0, 0x2112A442) . $txid;
        if (!defined send($socket, $request, 0, $target)) {
            record($id, 'send:' . errname($! + 0));
            close $socket;
            return;
        }
        record($id, 'sent');
        $results{$id}{local} = local_address($socket);
        my $reply = '';
        if (wait_readable($socket, 4.0)) {
            recv($socket, $reply, 1024, 0);
        }
        if (length($reply) >= 20 && unpack('n', $reply) == 0x0101 && substr($reply, 8, 12) eq $txid) {
            record($id, 'response');
            # XOR-MAPPED-ADDRESS (0x0020): the mapped port only; the address is the host's public egress, never kept.
            my $offset = 20;
            while ($offset + 4 <= length $reply) {
                my ($type, $length) = unpack('nn', substr($reply, $offset, 4));
                if ($type == 0x0020 && $length >= 8) {
                    $results{$id}{mappedPort} = unpack('n', substr($reply, $offset + 6, 2)) ^ 0x2112;
                    last;
                }
                $offset += 4 + (($length + 3) & ~3);
            }
        } else {
            record($id, 'noResponse');
        }
    }
    close $socket;
}

my $started = time;
my $seconds = $plan->{seconds} // 0;
my $interval = $plan->{interval} // 1;
my $rounds = 0;
my $lookups = 0;
while (1) {
    for my $probe (@{ $plan->{probes} }) {
        send_probe($probe) for 1 .. ($probe->{count} // 1);
    }
    for my $name (@{ $plan->{resolve} // [] }) {
        next unless $name =~ /^[a-z0-9.-]{1,200}$/;
        # The system resolver path (scoped DNS); bounded, output discarded.
        system('/usr/bin/perl', '-e', 'alarm shift; exec @ARGV or die', '8', '/usr/bin/dscacheutil', '-q', 'host', '-a', 'name', $name);
        $lookups++;
    }
    $rounds++;
    last if time - $started >= $seconds;
    sleep($interval);
}
my $result = {
    ok => JSON::PP::true, started => $started, ended => time, rounds => $rounds, lookups => $lookups,
    en0 => $en0, probes => \%results, order => \@order,
};
my $temporary = "$result_path.next";
open my $out, '>', $temporary or die "result unwritable\n";
print {$out} JSON::PP->new->canonical->encode($result);
close $out or die "result unwritable\n";
rename $temporary, $result_path or die "result unwritable\n";
