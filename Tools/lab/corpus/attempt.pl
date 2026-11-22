#!/usr/bin/perl
# SPDX-License-Identifier: MIT
# RT-17 attempt helpers, copied into the verdict stage as corpus-attempt.pl. Pure text processing: no command, no network.
#
#   attempt.pl watch OUT READY     reads `/usr/bin/log stream --style compact` on stdin; keeps "pid count" lines in OUT for libxpc's
#                                  code-signing refusal lines and the Lab daemon's own admission refusal (the refusing process logs them) and touches READY at the
#                                  stream's header. No log line is ever written.
#   attempt.pl report NAME CODE REPORT BEFORE AFTER LINES REFUSALS CLIENT_PID
#                                  one attempt's JSON: the client's exit code, fixed fields of its own report (none when it
#                                  wrote no parseable report), the refusal counts of the daemon (BEFORE's pid) and of the
#                                  client, both state snapshots and the lifecycle line count.
use strict;
use warnings;
use JSON::PP;

# libxpc (macOS 26 and 27): the listener's check-in drop, a forbidden message on an established connection, the session
# API's cancellation, and a connection's own failed requirement on its peer. A Lab daemon pins nothing on its listener
# (NSXPCDaemonListener.start): its delegate admits a client only when the audit token matches the installed app or CLI and
# otherwise logs this fixed line (LabClientAdmission) and declines the connection, so libxpc logs nothing for it.
my $refusal = qr/(?:Dropping check-in message|Received message forbidden) due to code signing requirement|Peer did not meet the code signing requirement|failed peer code signing requirement|Lab XPC client refused: its code matches neither the installed app nor the installed CLI/;

sub watch {
    my ($out, $ready) = @_;
    my %count;
    my $publish = sub {
        open my $file, '>', "$out.next" or die "refusal count unavailable\n";
        print {$file} map { "$_ $count{$_}\n" } sort { $a <=> $b } keys %count;
        close $file or die "refusal count unavailable\n";
        rename "$out.next", $out or die "refusal count unavailable\n";
    };
    $publish->();
    while (my $line = <STDIN>) {
        if ($line =~ /^(?:Filtering the log data|Timestamp\s)/) {
            open my $mark, '>', $ready or die "ready mark unavailable\n";
            close $mark;
            next;
        }
        next unless $line =~ /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+\s+\S+\s+\S+\[(\d{1,10}):[0-9a-fx]+\]/;
        my $pid = $1;
        next unless $line =~ $refusal;
        $count{$pid}++;
        $publish->();
    }
}

sub report {
    my ($name, $code, $report, $before, $after, $lines, $refusals, $client) = @_;
    my $state = decode_json($before);
    my %count = map { /^(\d{1,10}) (\d{1,6})$/ ? ($1 => 0 + $2) : () } split /\n/, $refusals;
    my $value = eval { decode_json($report) };
    my $kept;
    if (ref $value eq 'HASH') {
        $kept = {};
        for my $key (qw(error mode outcome phase protection)) {
            my $field = $value->{$key};
            $kept->{$key} = $field if defined $field && !ref $field && $field =~ /^[A-Za-z-]{1,40}$/;
        }
        my $error = $value->{errorCode};
        $kept->{errorCode} = 0 + $error if defined $error && !ref $error && $error =~ /^-?\d{1,6}$/;
        $kept->{impostor} = ($value->{impostor} ? JSON::PP::true : JSON::PP::false) if exists $value->{impostor};
    }
    my $daemon = $state->{daemonPid};
    die "client pid required\n" unless $client =~ /^[1-9]\d{0,9}$/;
    print JSON::PP->new->canonical->encode({name => $name, exitCode => 0 + $code, report => $kept,
        daemonRefusals => (defined $daemon && !ref $daemon && $daemon =~ /^[1-9]\d{0,9}$/ ? $count{$daemon} // 0 : undef),
        clientRefusals => $count{$client} // 0, before => $state, after => decode_json($after), lifecycleLines => 0 + $lines}), "\n";
}

my $mode = shift @ARGV // '';
if ($mode eq 'watch' && @ARGV == 2) {
    watch(@ARGV);
} elsif ($mode eq 'report' && @ARGV == 8 && $ARGV[1] =~ /^\d{1,3}$/ && $ARGV[5] =~ /^\d{1,6}$/) {
    report(@ARGV);
} else {
    die "usage: attempt.pl watch OUT READY | attempt.pl report NAME CODE REPORT BEFORE AFTER LINES REFUSALS CLIENT_PID\n";
}
