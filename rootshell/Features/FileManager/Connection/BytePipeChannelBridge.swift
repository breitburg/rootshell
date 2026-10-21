//
//  BytePipeChannelBridge.swift
//  rootshell
//
//  Exposes an AsyncBytePipe (e.g. a tssh exec channel running sftp-server)
//  as a NIO Channel, so Citadel's SFTPClient can speak over it. One end of
//  a socketpair becomes the Channel; the other is pumped to and from the pipe.
//

import Foundation
import NIOCore
import NIOPosix
import os.log

nonisolated enum BytePipeChannelBridge {
    private static let logger = Logger(subsystem: "com.rootshell", category: "FileManagerBridge")

    /// Returns a Channel carrying the pipe's bytes. Closing either side tears down both.
    /// Pass `autoRead: false` for a channel handed to `SSHClient.connect(on:)`,
    /// which must install its handlers before the server banner is read.
    static func makeChannel(for pipe: AsyncBytePipe, autoRead: Bool = true) async throws -> Channel {
        var fds: [Int32] = [0, 0]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else { throw POSIXError.current }

        let channel: Channel
        do {
            channel = try await NIOPipeBootstrap(group: MultiThreadedEventLoopGroup.singleton)
                .channelOption(ChannelOptions.autoRead, value: autoRead)
                .takingOwnershipOfDescriptor(inputOutput: fds[0])
                .get()
        } catch {
            close(fds[0])
            close(fds[1])
            throw error
        }

        let local = FileDescriptorBytePipe(fd: fds[1])
        let pumps = Task {
            await withTaskGroup(of: Void.self) { group in
                group.addTask { await pump(from: pipe, to: local, label: "remote→channel") }
                group.addTask { await pump(from: local, to: pipe, label: "channel→remote") }
                // Either direction ending means the session is over.
                await group.next()
                group.cancelAll()
            }
            await local.close()
            await pipe.close()
        }
        channel.closeFuture.whenComplete { _ in pumps.cancel() }
        return channel
    }

    private static func pump(from source: AsyncBytePipe, to sink: AsyncBytePipe, label: String) async {
        do {
            while !Task.isCancelled, let data = try await source.read(maxBytes: 256 * 1024) {
                try await sink.write(data)
            }
        } catch {
            logger.debug("Bridge \(label, privacy: .public) ended: \(error.localizedDescription, privacy: .public)")
        }
        // Unblock the opposite pump, which may be parked in a read.
        await source.close()
        await sink.close()
    }
}
