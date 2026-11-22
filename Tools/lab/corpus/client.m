// SPDX-License-Identifier: MIT
// RT-17 identity-corpus client. Runs only inside a lab VM (the guest guard's VM and marker test, repeated here before any
// XPC). The guest signs this one binary as the old-protocol and older-build clients, strips its x86_64 slice as the unsigned
// client (run under Rosetta: Apple silicon never executes unsigned arm64 code) and runs it as the user LaunchAgent impostor
// and its unprivileged control probe. It sets no requirement on the daemon, so only the daemon can refuse it.
//
//   client current SERVICE        privileged lookup; hello and stopCurrent at the current protocol version
//   client old-protocol SERVICE   privileged lookup; hello and stopCurrent at protocol version 6
//   client older-build SERVICE    privileged lookup; hello claiming client build 0, then stopCurrent
//   client probe-user SERVICE     unprivileged lookup (the user's own domain); hello
//   client serve SERVICE LOG      LaunchAgent impostor: accepts every connection, appends one line per connection to LOG
//
// Prints one JSON line: {"mode":..., "outcome":"refused"|"replied"|"timeout", "errorCode":N, "impostor":true|false}; a
// refusal's errorCode is the NSXPCConnection error (4097 interrupted, 4099 invalidated by the remote side).
// Envelopes are binary property lists shaped like WGEXDaemonProtocol's Codable Envelope (keyed enum cases).
#import <Foundation/Foundation.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>

@protocol WGEXCorpusDaemon
- (void)send:(NSData *)envelope reply:(void (^)(NSData *))reply;
@end

static NSString *const ImpostorMarker = @"wgex-corpus-impostor";

static BOOL InLabVM(void) {
    int present = 0;
    size_t size = sizeof(present);
    if (sysctlbyname("kern.hv_vmm_present", &present, &size, NULL, 0) != 0 || present != 1) {
        return NO;
    }
    struct stat marker;
    return lstat("/var/db/wgex-lab-host", &marker) == 0 && S_ISREG(marker.st_mode) && marker.st_uid == 0
        && (marker.st_mode & 07777) == 0644;
}

static NSData *Envelope(NSInteger version, NSDictionary *body) {
    NSDictionary *envelope = @{@"protocolVersion" : @(version), @"requestID" : NSUUID.UUID.UUIDString, @"body" : body};
    return [NSPropertyListSerialization dataWithPropertyList:envelope format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
}

static NSDictionary *Hello(NSInteger build) {
    return @{@"hello" : @{@"clientVersion" : @"0.0.0", @"clientBuild" : @(build)}};
}

static NSDictionary *StopCurrent(void) {
    return @{@"stopCurrent" : @{@"reason" : @"userRequested"}};
}

static void Report(NSString *mode, NSString *outcome, NSInteger code, BOOL impostor) {
    NSDictionary *line = @{@"mode" : mode, @"outcome" : outcome, @"errorCode" : @(code), @"impostor" : @(impostor)};
    NSData *data = [NSJSONSerialization dataWithJSONObject:line options:NSJSONWritingSortedKeys error:NULL];
    if (data != nil) {
        fwrite(data.bytes, 1, data.length, stdout);
        fputc('\n', stdout);
    }
}

// One request on the connection; returns the reply, or nil with *code set (0 for a timeout).
static NSData *Send(NSXPCConnection *connection, NSData *envelope, NSInteger *code) {
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block NSData *answer = nil;
    __block NSInteger failure = 0;
    id<WGEXCorpusDaemon> proxy = [connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
        failure = error.code != 0 ? error.code : -1;
        dispatch_semaphore_signal(done);
    }];
    [proxy send:envelope
          reply:^(NSData *reply) {
              answer = reply;
              dispatch_semaphore_signal(done);
          }];
    if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC)) != 0) {
        *code = 0;
        return nil;
    }
    *code = failure;
    return answer;
}

static int Client(NSString *mode, NSString *service) {
    BOOL privileged = ![mode isEqualToString:@"probe-user"];
    NSInteger version = [mode isEqualToString:@"old-protocol"] ? 6 : 7;
    NSInteger build = [mode isEqualToString:@"older-build"] ? 0 : 1;
    NSXPCConnection *connection =
        [[NSXPCConnection alloc] initWithMachServiceName:service options:privileged ? NSXPCConnectionPrivileged : 0];
    connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(WGEXCorpusDaemon)];
    [connection resume];
    NSInteger code = 0;
    NSData *reply = Send(connection, Envelope(version, Hello(build)), &code);
    if (reply == nil) {
        [connection invalidate];
        Report(mode, code == 0 ? @"timeout" : @"refused", code, NO);
        return 0;
    }
    BOOL impostor = [reply isEqualToData:[ImpostorMarker dataUsingEncoding:NSUTF8StringEncoding]];
    if (privileged && !impostor) {
        // Identity was accepted: send the privileged work too, so state and the daemon log show what it did.
        NSInteger ignored = 0;
        (void)Send(connection, Envelope(version, StopCurrent()), &ignored);
    }
    [connection invalidate];
    Report(mode, @"replied", 0, impostor);
    return 0;
}

@interface Impostor : NSObject <NSXPCListenerDelegate, WGEXCorpusDaemon>
@property(nonatomic, copy) NSString *log;
@end

@implementation Impostor
- (BOOL)listener:(NSXPCListener *__unused)listener shouldAcceptNewConnection:(NSXPCConnection *)connection {
    int file = open(self.log.fileSystemRepresentation, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, 0600);
    if (file >= 0) {
        (void)write(file, "connection\n", 11);
        close(file);
    }
    connection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(WGEXCorpusDaemon)];
    connection.exportedObject = self;
    [connection resume];
    return YES;
}

- (void)send:(NSData *__unused)envelope reply:(void (^)(NSData *))reply {
    reply([ImpostorMarker dataUsingEncoding:NSUTF8StringEncoding]);
}
@end

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (!InLabVM()) {
            fputs("corpus: lab VM required\n", stderr);
            return 2;
        }
        if (argc < 3) {
            fputs("usage: client current|old-protocol|older-build|probe-user SERVICE | client serve SERVICE LOG\n", stderr);
            return 64;
        }
        NSString *mode = @(argv[1]);
        NSString *service = @(argv[2]);
        if ([mode isEqualToString:@"serve"] && argc == 4) {
            Impostor *impostor = [Impostor new];
            impostor.log = @(argv[3]);
            NSXPCListener *listener = [[NSXPCListener alloc] initWithMachServiceName:service];
            listener.delegate = impostor;
            [listener resume];
            dispatch_main();
        }
        if (argc == 3 && ([mode isEqualToString:@"current"] || [mode isEqualToString:@"old-protocol"]
                          || [mode isEqualToString:@"older-build"] || [mode isEqualToString:@"probe-user"])) {
            return Client(mode, service);
        }
        fputs("corpus: unknown mode\n", stderr);
        return 64;
    }
}
