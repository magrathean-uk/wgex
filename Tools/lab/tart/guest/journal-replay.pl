#!/usr/bin/perl
# SPDX-License-Identifier: MIT
# M1-12b. Print the daemon journal as the daemon itself restores it: the flat schema-2 checkpoint journal.json (document
# fields at the root plus journalSequence) with every committed journal.log record replayed on top. While a cutover trial
# is armed the checkpoint is usually the one written when the trial was armed and its generation allocated; the trial's
# resources and pf token are appended to journal.log afterwards and reach journal.json only at the next checkpoint.
# DaemonJournal.commit also checkpoints once journal.log passes 64 KiB and before an append that would pass 8 MiB, so a
# long armed trial can have resources in journal.json too; the replay handles every case. Mirrors
# JournalRecord.replay/apply/restoreResources and DaemonJournal.compact in
# Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Storage. Read-only; prints one JSON document on stdout, no diagnostics
# with journal content. Needs only the system Perl's core JSON::PP, Digest::SHA and B (guest run 7 on 26.6.2: perl 5.34.1,
# JSON::PP 4.06, Digest::SHA 6.02, also under sudo -n). Usage: journal-replay.pl STATE-DIRECTORY >0600-FILE
# stdout carries the whole document including pfToken in full: always redirect it to a 0600 file (umask 077), never to a
# terminal or a log, and remove the file when done.
use strict;
use warnings;
use B ();
use Digest::SHA qw(sha256);
use JSON::PP;

@ARGV == 1 or die "usage: journal-replay.pl STATE-DIRECTORY >0600-FILE (stdout carries the pf token; redirect it to a 0600 file)\n";
my $directory = $ARGV[0];
# UTF-8 in and out (M1-12d FIX1-VERIFY N4): journal bytes decode as UTF-8 and the document is encoded back to UTF-8
# octets, so a \u escape above U+00FF or raw CJK in a journal string never reaches print as a wide character (whose
# warning the catch-all below would turn into a refusal). Raw UTF-8 input round-trips byte for byte; invalid UTF-8 is
# refused as journal invalid.
my $json = JSON::PP->new->utf8->canonical;
my $limit = 8 * 1024 * 1024 - 36;

sub slurp {
    my ($path, $optional) = @_;
    my $file;
    unless (open $file, '<:raw', $path) {
        return '' if $optional && $!{ENOENT};
        die "journal unreadable\n";
    }
    local $/;
    my $data = <$file>;
    close $file or die "journal unreadable\n";
    return defined $data ? $data : '';
}

sub object {
    my ($value, $message) = @_;
    die $message // "journal invalid\n" unless ref $value eq 'HASH';
    return $value;
}

# Every container is type-checked before it is dereferenced: Perl's strict-refs error would quote the journal value.
sub array {
    my ($value, $message) = @_;
    die $message unless ref $value eq 'ARRAY';
    return $value;
}

# `removed` lists keys ([String] in the daemon): every element must be a defined plain scalar, never null or a container.
sub key_list {
    my ($value, $message) = @_;
    for my $key (@{ array($value, $message) }) {
        die $message unless defined $key && !ref $key;
    }
    return $value;
}

# The daemon decodes journalSequence, generations and record sequences as UInt64 (DaemonJournalRecord.swift
# decodeIfPresent(UInt64.self)): at most 20 ASCII digits and at most 18446744073709551615 (FIX1-VERIFY N1). Checked as
# text before any numeric use, so an out-of-range value is refused rather than skipping every log record as already
# checkpointed or comparing as a float. It must also be a JSON number: JSON::PP decodes a JSON string such as "42" to a
# string-only scalar, which the daemon's UInt64 decode rejects (M1-10h VERIFY N6). The flags are read on the copy before
# the pattern match stringifies it, so the caller's value keeps its number form for the canonical output.
sub uint64 {
    my ($value) = @_;
    return 0 unless defined $value && !ref $value && B::svref_2object(\$value)->FLAGS & (B::SVp_IOK | B::SVp_NOK);
    return 0 unless $value =~ /\A[0-9]{1,20}\z/;
    return length($value) < 20 || $value le '18446744073709551615';
}

# Catch-all: a Perl warning can quote the value it is about, so any warning ends the replay with a fixed message.
local $SIG{__WARN__} = sub { die "journal invalid\n" };
my $checkpoint = slurp("$directory/journal.json", 0);
my $document = object(eval { $json->decode($checkpoint) } // die "journal invalid\n");
my $sequence = delete $document->{journalSequence} // 0;
die "journal checkpoint invalid\n" unless uint64($sequence);
die "journal invalid version\n" unless defined $document->{schemaVersion} && $document->{schemaVersion} =~ /\A[12]\z/;

# Generations are UInt64 in the daemon. Anything else is refused before a numeric comparison, whose warning would quote
# the journal value. $message names the file at fault: the checkpoint or the log.
sub generation_number {
    my ($value, $message) = @_;
    die $message unless uint64($value);
    return $value;
}

# GenerationResources(generation:) as JSONEncoder writes it: nil optionals are omitted.
sub fresh_resource {
    my ($generation) = @_;
    return { generation => $generation, attemptedSteps => [], addresses => [], routeFlags => 0x4000, routes => [] };
}

sub restore_resources {
    my ($edits, $previous) = @_;
    my $invalid = "journal log invalid\n";
    object($_, $invalid) for @{ array($previous, $invalid) };
    my @restored;
    for my $edit (@{ array($edits, $invalid) }) {
        object($edit, $invalid);
        my $generation = generation_number($edit->{generation}, $invalid);
        my ($old) = grep { defined $_->{generation} && generation_number($_->{generation}, $invalid) == $generation } @$previous;
        my %values = %{ $old // fresh_resource($generation) };
        delete $values{$_} for @{ key_list($edit->{removed} // [], $invalid) };
        my $changed = object($edit->{set}, $invalid);
        $values{$_} = $changed->{$_} for keys %$changed;
        push @restored, \%values;
    }
    return \@restored;
}

sub compact {
    my ($value, $message) = @_;
    my $current = generation_number($value->{generation} // 0, $message);
    my @entries = grep {
        my $generation = generation_number(object($_, $message)->{generation}, $message);
        $generation == $current || ($current > 0 && $generation == $current - 1)
    } @{ array($value->{entries} // [], $message) };
    my (%seen, @kept);
    for my $entry (reverse @entries) {
        my $key = $json->encode($entry);
        unshift @kept, $entry unless $seen{$key}++;
    }
    $value->{entries} = \@kept;
}

sub apply {
    my ($record) = @_;
    my $invalid = "journal log invalid\n";
    my $changed = $record->{set} // {};
    my $removed = key_list($record->{removed} // [], $invalid);
    my %next = %$document;
    delete $next{$_} for @$removed;
    $next{$_} = $changed->{$_} for keys %{ object($changed, $invalid) };
    my @entries = $record->{replaceEntries} ? () : @{ array($document->{entries} // [], $invalid) };
    $next{entries} = [@entries, @{ array($record->{entries} // [], $invalid) }];
    $next{resources} = restore_resources($record->{resources}, $next{resources} // []) if defined $record->{resources};
    compact(\%next, $invalid);
    $document = \%next;
}

compact($document, "journal checkpoint invalid\n");
my $log = slurp("$directory/journal.log", 1);
my ($offset, $last) = (0, 0);
while ($offset + 4 <= length $log) {
    my $length = unpack 'V', substr($log, $offset, 4);
    my $size = $length & 0x7FFF_FFFF;
    my $bookkeeping = $length & 0x8000_0000;
    last if $size == 0 && substr($log, $offset) =~ /\A\0*\z/;
    die "journal log invalid\n" unless $size > 0 && $size <= $limit;
    last if $offset + $size + 36 > length $log;
    my $body = substr($log, $offset + 4, $size);
    if (sha256($body) ne substr($log, $offset + 4 + $size, 32)) {
        # Only a torn bookkeeping tail is discardable; any other checksum failure is corruption.
        last if $offset + $size + 36 == length($log) && $bookkeeping;
        die "journal log invalid\n";
    }
    my $record = object(eval { $json->decode($body) } // die "journal log invalid\n");
    my $number = $record->{sequence};
    die "journal log invalid\n" unless uint64($number);
    die "journal log invalid\n" if ($bookkeeping && $record->{durable}) || $number <= $last;
    $last = $number;
    if ($number > $sequence) {
        die "journal log invalid\n" unless $number == $sequence + 1;
        apply($record);
        $sequence = $number;
    }
    $offset += $size + 36;
}
$document->{schemaVersion} = 2;
$document->{journalSequence} = $sequence;
print $json->encode($document), "\n";
