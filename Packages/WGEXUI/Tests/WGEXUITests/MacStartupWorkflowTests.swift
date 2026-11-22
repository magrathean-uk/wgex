// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXTesting
    import WGEXUI

    @MainActor
    private struct MacStartupWorkflowTests {
        @Test func `startup coordinates boot intent login item and local cache with rollback`() async throws {
            var calls: [String] = []
            var failLogin = false
            let controller = MacStartupController(
                saveDaemon: { _, option in calls.append("daemon-" + option.rawValue) },
                setLoginItem: { enabled in
                    calls.append(enabled ? "login-on" : "login-off")
                    if failLogin, enabled {
                        throw TunnelError.permissionDenied
                    }
                },
                saveDocument: { calls.append("cache-" + MacStartupOption(options: $0.macOptions).rawValue) },
            )
            let profile = TunnelProfile(name: "Startup")
            for option in MacStartupOption.allCases {
                calls = []
                try await controller.save(profile, option: option)
                #expect(calls == ["daemon-" + option.rawValue, option == .login ? "login-on" : "login-off", "cache-" + option.rawValue])
            }
            calls = []; failLogin = true
            await #expect(throws: TunnelError.permissionDenied) { try await controller.save(profile, option: .login) }
            #expect(calls == ["daemon-login", "login-on", "daemon-off", "login-off", "cache-off"])
        }

        @Test func `login item remains on for another profile and rollback uses the aggregate`() async throws {
            var first = TunnelProfile(name: "First")
            var second = TunnelProfile(name: "Second")
            first.macOptions.autoConnectAtLogin = true
            second.macOptions.autoConnectAtLogin = true
            var documents = [first, second]
            var login: [Bool] = []
            var fail = false
            let controller = MacStartupController(
                saveDaemon: { _, _ in }, setLoginItem: { login.append($0) },
                saveDocument: { updated in
                    if fail {
                        throw ServiceError.system(code: 5)
                    }
                    documents = documents.map { $0.id == updated.id ? updated : $0 }
                }, loadProfiles: { documents },
            )
            try await controller.save(first, option: .off)
            #expect(login == [true])
            fail = true
            await #expect(throws: ServiceError.system(code: 5)) { try await controller.save(second, option: .off) }
            #expect(login.suffix(2) == [false, true])
            fail = false
            try await controller.save(second, option: .off)
            #expect(login.last == false)
        }

        @Test func `login item system errors have login recovery copy`() async {
            let controller = MacStartupController(
                saveDaemon: { _, _ in }, setLoginItem: { _ in throw ServiceError.system(code: 5) }, saveDocument: { _ in },
            )
            await #expect(throws: MacWorkflowError.loginItem) { try await controller.save(TunnelProfile(name: "Login"), option: .login) }
        }

        @Test func `editor startup uses the shell guard and the same acknowledged path`() async throws {
            var calls: [MacStartupOption] = []
            let model = MacShellModel(dependencies: .init(
                backend: WGEXTesting.FakeTunnelBackend(), service: WGEXTesting.FakeServiceController(initial: .enabled),
                simulated: true, operations: .init(
                    saveStartup: { _, option in calls.append(option) },
                    secureInstall: { .verified },
                    refreshDaemon: { true },
                ),
            ))
            var profile = TunnelProfile(name: "Editor")
            await #expect(throws: MacWorkflowError.secureInstallRequired) { try await model.persistStartup(profile, option: .boot) }
            #expect(calls.isEmpty)
            await model.refreshService(); await model.verifySecureInstall()
            try await model.persistStartup(profile, option: .boot)
            profile.macOptions = MacStartupOption.boot.profileOptions
            try await model.persistStartup(profile, option: .login)
            profile.macOptions = MacStartupOption.login.profileOptions
            try await model.persistStartup(profile, option: .off)
            #expect(calls == [.boot, .login, .off])
        }
    }
#endif
