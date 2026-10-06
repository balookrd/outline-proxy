import Foundation

/// Manages persistent storage of server profiles in Application Support.
public final class ProfileStore: @unchecked Sendable {
    public static let shared = ProfileStore()

    private let lock = NSLock()
    private let fileURL: URL
    private var cachedProfiles: [ServerProfile] = []
    private var selectedId: String?

    public var onProfilesChanged: (@Sendable () -> Void)?

    private init() {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            .appendingPathComponent("OutlineProxy")
        try? FileManager.default.createDirectory(at: appSupport, withIntermediateDirectories: true)
        self.fileURL = appSupport.appendingPathComponent("profiles.json")
        load()
    }

    public var profiles: [ServerProfile] {
        lock.lock()
        defer { lock.unlock() }
        return cachedProfiles
    }

    public var activeProfile: ServerProfile? {
        lock.lock()
        defer { lock.unlock() }
        if let id = selectedId {
            return cachedProfiles.first { $0.id == id }
        }
        return cachedProfiles.first
    }

    public var activeProfileId: String? {
        lock.lock()
        defer { lock.unlock() }
        return selectedId ?? cachedProfiles.first?.id
    }

    public func selectProfile(id: String) {
        lock.lock()
        selectedId = id
        saveInternal()
        lock.unlock()
        onProfilesChanged?()
    }

    public func addProfile(_ profile: ServerProfile) {
        lock.lock()
        cachedProfiles.append(profile)
        if selectedId == nil {
            selectedId = profile.id
        }
        saveInternal()
        lock.unlock()
        onProfilesChanged?()
    }

    public func updateProfile(_ profile: ServerProfile) {
        lock.lock()
        if let idx = cachedProfiles.firstIndex(where: { $0.id == profile.id }) {
            cachedProfiles[idx] = profile
            saveInternal()
        }
        lock.unlock()
        onProfilesChanged?()
    }

    public func removeProfile(id: String) {
        lock.lock()
        cachedProfiles.removeAll { $0.id == id }
        if selectedId == id {
            selectedId = cachedProfiles.first?.id
        }
        saveInternal()
        lock.unlock()
        onProfilesChanged?()
    }

    private struct StorageData: Codable {
        var profiles: [ServerProfile]
        var selectedId: String?
    }

    private func load() {
        lock.lock()
        defer { lock.unlock() }

        guard let data = try? Data(contentsOf: fileURL),
              let storage = try? JSONDecoder().decode(StorageData.self, from: data) else {
            // Default initial profile
            return
        }

        self.cachedProfiles = storage.profiles
        self.selectedId = storage.selectedId
    }

    private func saveInternal() {
        let storage = StorageData(profiles: cachedProfiles, selectedId: selectedId)
        if let data = try? JSONEncoder().encode(storage) {
            try? data.write(to: fileURL, options: .atomic)
        }
    }
}
