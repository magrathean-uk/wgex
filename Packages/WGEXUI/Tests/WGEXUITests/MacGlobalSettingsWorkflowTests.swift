// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXDaemonProtocol
    import WGEXUI

    @MainActor
    private struct MacGlobalSettingsWorkflowTests {
        @Test func `only an admin challenge opens a prompt and cancellation cannot acknowledge settings`() async throws {
            var authorised: [Bool] = []
            var prompts = 0
            var cancel = false
            let controller = MacGlobalSettingsController(send: { _, authorization in
                authorised.append(authorization != nil)
                if authorization == nil {
                    throw DaemonError.notAuthorised(.adminRightRequired)
                }
            }, grant: {
                prompts += 1
                if cancel {
                    throw TunnelError.cancelled
                }
                return Data()
            })
            let value = try await controller.set(.defaults)
            #expect(value == .defaults)
            #expect(authorised == [false, true])
            #expect(prompts == 1)
            cancel = true; authorised = []
            await #expect(throws: TunnelError.cancelled) { try await controller.set(.defaults) }
            #expect(authorised == [false])
        }

        @Test func `ordinary settings acceptance never opens the admin prompt`() async throws {
            var prompts = 0
            let controller = MacGlobalSettingsController(send: { _, _ in }, grant: { prompts += 1; return Data() })
            #expect(try await controller.set(.defaults) == .defaults)
            #expect(prompts == 0)
        }
    }
#endif
