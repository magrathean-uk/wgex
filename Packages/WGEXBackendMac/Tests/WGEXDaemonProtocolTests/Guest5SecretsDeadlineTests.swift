// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
import WGEXDaemonProtocol

@Suite(.timeLimit(.minutes(1)))
private struct Guest5SecretsDeadlineTests {
    @Test
    func `unanswered app callback times out closed and ignores late duplicate replies`() async {
        let proxy = SilentSecretsProxy(), budgets = Mutex<[Duration]>([])
        let clock = XPCClock(now: { 0 }, sleep: { budget in budgets.withLock { $0.append(budget) } })
        let callback = NSXPCDaemonListener.secretsCallback(proxy: { _ in proxy }, clock: clock)
        // Unblock the unfixed implementation as well, so the regression fails without hanging.
        let fallback = Task {
            try? await ContinuousClock().sleep(for: .milliseconds(250))
            if !Task.isCancelled {
                proxy.replyLate()
            }
        }
        await #expect(throws: DaemonFailure(wire: .tunnel(.timedOut))) { _ = try await callback(UUID()) }
        #expect(budgets.withLock { $0 } == [.seconds(5)])
        fallback.cancel(); await fallback.value
        proxy.replyLate(); proxy.replyLate()
    }
}

private final class SilentSecretsProxy: NSObject, WGEXClientEventsXPC, Sendable {
    private let reply = Mutex<(@Sendable (Data) -> Void)?>(nil)
    func event(_: Data) {}
    func provideSecrets(_: Data, reply: @escaping @Sendable (Data) -> Void) {
        self.reply.withLock { $0 = reply }
    }

    func replyLate() {
        reply.withLock { $0 }?(Data())
    }
}
