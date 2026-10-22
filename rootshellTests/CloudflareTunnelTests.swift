import XCTest

final class CloudflareTunnelTests: XCTestCase {

    // MARK: - Matching

    func testPatternsMatchExactWildcardAndNegated() {
        var tunnel = CloudflareTunnel()
        tunnel.hostPatterns = "ssh.example.com, *.corp.example.com !www.corp.example.com"
        XCTAssertTrue(tunnel.matches(host: "ssh.example.com"))
        XCTAssertTrue(tunnel.matches(host: "SSH.Example.com."))
        XCTAssertTrue(tunnel.matches(host: "db.corp.example.com"))
        XCTAssertFalse(tunnel.matches(host: "www.corp.example.com"))
        XCTAssertFalse(tunnel.matches(host: "example.com"))
        XCTAssertFalse(tunnel.matches(host: ""))
    }

    func testRouteSkipsDisabledTunnels() {
        var disabled = CloudflareTunnel()
        disabled.hostPatterns = "ssh.example.com"
        disabled.isEnabled = false
        var enabled = CloudflareTunnel()
        enabled.hostPatterns = "*.example.com"
        XCTAssertEqual(CloudflareTunnel.route(for: "ssh.example.com", in: [disabled, enabled])?.id, enabled.id)
        XCTAssertNil(CloudflareTunnel.route(for: "ssh.example.org", in: [disabled, enabled]))
    }

    // MARK: - Endpoint

    func testEndpointConnectsToDialedHost() throws {
        var tunnel = CloudflareTunnel()
        tunnel.hostPatterns = "ssh.example.com"
        let endpoint = try XCTUnwrap(tunnel.endpoint(host: "SSH.example.com", port: 22))
        XCTAssertEqual(endpoint.hostname, "ssh.example.com")
        XCTAssertEqual(endpoint.url.absoluteString, "wss://ssh.example.com")
        XCTAssertNil(endpoint.jumpDestination)
    }

    func testBastionEndpointSendsDestination() throws {
        var tunnel = CloudflareTunnel()
        tunnel.hostPatterns = "*.internal"
        tunnel.bastionHostname = "https://bastion.example.com/"
        let endpoint = try XCTUnwrap(tunnel.endpoint(host: "db.internal", port: 2222))
        XCTAssertEqual(endpoint.hostname, "bastion.example.com")
        XCTAssertEqual(endpoint.url.absoluteString, "wss://bastion.example.com")
        XCTAssertEqual(endpoint.jumpDestination, "db.internal:2222")
        XCTAssertEqual(tunnel.endpoint(host: "fd00::1", port: 22)?.jumpDestination, "[fd00::1]:22")
    }

    // MARK: - Validation

    func testValidation() {
        var tunnel = CloudflareTunnel()
        XCTAssertNotNil(tunnel.validationError)
        tunnel.hostPatterns = "!ssh.example.com"
        XCTAssertNotNil(tunnel.validationError)
        tunnel.hostPatterns = "ssh.example.com"
        XCTAssertNil(tunnel.validationError)
        tunnel.bastionHostname = "not a host"
        XCTAssertNotNil(tunnel.validationError)
    }

    func testDecodingToleratesMissingAndRetiredFields() throws {
        let id = UUID()
        let json = Data(#"{"id":"\#(id.uuidString)","hostPatterns":"ssh.example.com","authMode":"serviceToken","serviceTokenID":"x"}"#.utf8)
        let tunnel = try JSONDecoder().decode(CloudflareTunnel.self, from: json)
        XCTAssertEqual(tunnel.id, id)
        XCTAssertEqual(tunnel.hostPatterns, "ssh.example.com")
        XCTAssertTrue(tunnel.isEnabled)
    }

    // MARK: - ProxyCommand

    func testParsesDocumentedProxyCommand() throws {
        let parsed = try XCTUnwrap(CloudflaredProxyCommand.parse("/usr/local/bin/cloudflared access ssh --hostname %h", host: "ssh.example.com"))
        XCTAssertNil(parsed.hostname)
        let tunnel = parsed.tunnel(for: "ssh.example.com")
        XCTAssertEqual(tunnel.hostPatterns, "ssh.example.com")
        XCTAssertNil(tunnel.trimmedBastionHostname)
    }

    func testParsesDestinationAndSkipsTokenFlags() throws {
        let command = #"cloudflared --loglevel debug access ssh --hostname=jump.example.com --destination %h:22 --id "abc.access" --service-token-secret 's3cr et'"#
        let parsed = try XCTUnwrap(CloudflaredProxyCommand.parse(command, host: "db.internal"))
        XCTAssertEqual(parsed.hostname, "jump.example.com")
        XCTAssertEqual(parsed.destination, "db.internal:22")
        let tunnel = parsed.tunnel(for: "db.internal")
        XCTAssertEqual(tunnel.hostPatterns, "db.internal")
        XCTAssertEqual(tunnel.bastionHostname, "jump.example.com")
    }

    func testRejectsOtherProxyCommands() {
        XCTAssertNil(CloudflaredProxyCommand.parse("ssh -W %h:%p bastion", host: "a"))
        XCTAssertNil(CloudflaredProxyCommand.parse("cloudflared tunnel run", host: "a"))
        XCTAssertNil(CloudflaredProxyCommand.parse("cloudflared access ssh", host: "a"))
    }
}
