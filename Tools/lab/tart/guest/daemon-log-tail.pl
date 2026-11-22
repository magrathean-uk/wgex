#!/usr/bin/perl
# SPDX-License-Identifier: MIT
# Reconstruct public diagnostic fields before writing a bounded stream tail.
use strict;
use warnings;
my $stage = shift @ARGV or die "stream stage required\n";
my @tail;
my $events = 0;
my $omitted = 0;    # length of the run of omitted events that ends the tail
my %types = map { $_ => 1 } qw(HostAdapterError PacketFilterFailure DaemonPortError StateDirectoryError FloorError EngineError SecretStoreError DaemonJournalError UnknownError);
my %labels = map { $_ => 1 } qw(system labRequired missingKey noPrimaryInterface alreadyStarted operationInProgress unsupportedPlatform unboundInterfaces unsafePath unsafeMetadata tooLarge invalidDocument downgradeDetected invalidArgument outOfMemory invalidHandle tun bind config up state abiMismatch deviceClosed internal unknown locked notFound duplicate unavailable staleGeneration exhausted invalidVersion process verification deadline token journal invalidInput notOwned timedOut noAnswer withheld);
# Lab-only ownership verdicts (M1-17/M1-18): the fixed labels of DaemonDiagnostics.ownershipLabels,
# its "unknown" fallback, and the interface fence line with its fixed check labels (M1-10d L20).
my $ownership_event = qr/tunnel identity (?:drift|missing)|tunnel descriptor missing|canary identity drift|route interface drift|device interface drift|canary interface missing|foreign route|tunnel route missing|canary route missing|policy mismatch|dns unverified|engine interface (?:mismatch|missing)|canary (?:adopted|replaced)|unknown/;
my $ownership_interface = qr/interface [a-z]{1,8}\d{1,3} index \d{1,5}->(?:absent|\d{1,5} check (?:index|descriptor|link address|address|unknown))/;
my @messages = (
    'Protection verification failed; state unknown', 'Network verification failed; protection unknown',
    'Owned pf enable reference was externally released; reacquiring', 'Orderly shutdown is waiting for blocking policy',
    'Previous daemon shutdown was orderly', 'Previous daemon shutdown was not recorded as orderly',
    'Daemon listening; recovering', 'Daemon state directory unusable or minimum build refused',
    'Lab host guard refused an adapter', 'Lab adapter failure; detailed data withheld',
    'Engine restored the previous live configuration', 'start:secrets',
);
sub publish {
    my ($name, $data) = @_;
    my $target = "$stage/$name";
    die "unsafe stream output\n" if -l $target || -l "$target.next";
    open my $file, '>', "$target.next" or die "stream output unavailable\n";
    print {$file} $data;
    close $file or die "stream output unavailable\n";
    rename "$target.next", $target or die "stream output unavailable\n";
}
while (my $line = <STDIN>) {
    next if $line =~ /^(?:Filtering the log data|Timestamp\s)/;
    $events++;
    my $message;
    if ($line =~ /\b(start|stop|recover|recovery|reconfigure|update|handoff|reconcile|request) failed, type: ([A-Za-z]+) case: ([A-Za-z]+) code: (-?\d{1,11})\b/ && $types{$2} && $labels{$3}) {
        $message = "$1 failed, type: $2 case: $3 code: $4";
    } elsif ($line =~ /\bLab system adapter failure, code: (-?\d{1,11})\b/) {
        $message = "Lab system adapter failure, code: $1";
    } elsif ($line =~ /\bstatus: phase=([a-z]{1,32}) protection=(protected|blocked|unprotected|unknown) reason=([A-Za-z]{1,40})\b/) {
        # Fixed-vocabulary state line (M1-15 L7); enum case names only.
        $message = "status: phase=$1 protection=$2 reason=$3";
    } elsif ($line =~ /\bverifier: ([A-Za-z]{1,40})\b/) {
        $message = "verifier: $1";
    } elsif ($line =~ /\bpf: (token (?:acquired|released|recovered)|reference leaked)\b/) {
        $message = "pf: $1";
    } elsif ($line =~ /\bownership: ($ownership_event|$ownership_interface)$/) {
        # Anchored at the end of the line: a known shape followed by any other text is omitted.
        $message = "ownership: $1";
    } else {
        for my $known (@messages) {
            if (index($line, $known) >= 0) { $message = $known; last; }
        }
    }
    my $stamp = $line =~ /^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?)/ ? "$1 " : '';
    if (defined $message) {
        $omitted = 0;
    } else {
        # A run of omitted events is one counted line, so noise cannot push the
        # allowlisted status, verifier and pf lines out of the 50-line tail.
        pop @tail if $omitted++;
        $message = $omitted > 1 ? "<$omitted events omitted; non-diagnostic content>" : '<event omitted; non-diagnostic content>';
    }
    push @tail, $stamp . $message;
    shift @tail while @tail > 50;
    publish('daemon-log-tail', join("\n", @tail) . "\n");
    publish('daemon-log-count', "events=$events; rawMessagesOmitted=1\n");
}
