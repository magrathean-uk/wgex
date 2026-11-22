#!/usr/bin/perl
# SPDX-License-Identifier: MIT
# Reduce status and pf read-back to public evidence. The owner token never leaves this process.
use strict;
use warnings;
use JSON::PP;
use Digest::SHA qw(sha256_hex);
my ($at, $pid, $references, $info, $rules) = @ARGV;
$rules = '' unless defined $rules;
local $/;
my $raw = decode_json(<STDIN>);
my $token = $raw->{ownerPFToken};
my $owned = defined($token) && !ref($token) && $token =~ /^[1-9][0-9]{0,19}$/;
my @tokens = $references =~ /^\s*\d+\s+\S+\s+(\d+)\s+\d+ days/gm;
my %policies = map { $_ => 1 } qw(disconnected connecting connected disconnecting error lockdown captiveWindow);

# The fields one status publication shares with the `startup` record (DEC-018); anything else, the token included, stays.
sub publication {
    my ($value) = @_;
    my $policy = $value->{journalPolicy};
    if (ref($policy) eq 'HASH' && keys(%$policy) == 1) { ($policy) = keys %$policy; }
    $policy = undef unless defined($policy) && !ref($policy) && $policies{$policy};
    my $sequence = $value->{sequence};
    # Numified so the JSON is a number whatever the guest perl did to the scalar.
    $sequence = defined($sequence) && !ref($sequence) && $sequence =~ /^[0-9]{1,20}$/ ? 0 + $sequence : undef;
    my $measured = $value->{measuredAt};
    $measured = undef unless defined($measured) && !ref($measured) && $measured =~ /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/;
    my $protection = $value->{protection};
    $protection = undef unless defined($protection) && !ref($protection) && $protection =~ /^(protected|blocked|unprotected|unknown|captiveWindow|unsupported)$/;
    return (sequence => $sequence, measuredAt => $measured, journalPolicy => $policy, protection => $protection);
}

my $phase = $raw->{phase};
$phase = undef unless defined($phase) && !ref($phase) && $phase =~ /^(idle|preparing|configuring|active|reasserting|captiveWindow|stopping|failed)$/;
# The run's first publication as the daemon keeps it, or null when absent (before it exists, or from an older daemon).
my $startup = ref($raw->{startup}) eq 'HASH' ? { publication($raw->{startup}) } : undef;
my %out = (at => 0 + $at, pid => 0 + $pid, publication($raw), phase => $phase, startup => $startup,
    referenceCount => scalar(@tokens), pfEnabled => $info =~ /^Status:\s+Enabled\b/m ? JSON::PP::true : JSON::PP::false,
    ownerPFTokenPresent => $owned ? JSON::PP::true : JSON::PP::false,
    ownerPFTokenHash => $owned ? substr(sha256_hex($token), 0, 12) : undef,
    # Digest of the anchor's loaded rules (`pfctl -a com.apple/wgex -sr`), null when the anchor holds none; the rules never leave.
    rulesDigest => $rules =~ /\S/ ? substr(sha256_hex($rules), 0, 12) : undef,
    ownerInReferences => $owned && grep($_ eq $token, @tokens) ? JSON::PP::true : JSON::PP::false);
print JSON::PP->new->canonical->encode(\%out), "\n";
