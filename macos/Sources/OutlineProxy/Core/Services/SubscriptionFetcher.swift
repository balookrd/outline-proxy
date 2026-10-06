import Foundation

/// Fetches config subscriptions from remote HTTPS URLs.
public enum SubscriptionFetcher {

    public static func updateSubscription(_ profile: ServerProfile) async throws -> ServerProfile {
        guard let url = URL(string: profile.configUrl) else {
            throw NSError(domain: "SubscriptionFetcher", code: 1, userInfo: [NSLocalizedDescriptionKey: "Некорректный URL подписки"])
        }

        var request = URLRequest(url: url)
        request.timeoutInterval = 15
        request.setValue("OutlineProxy-macOS/1.0", forHTTPHeaderField: "User-Agent")

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) else {
            throw NSError(domain: "SubscriptionFetcher", code: 2, userInfo: [NSLocalizedDescriptionKey: "Ошибка загрузки: статус HTTP не успешен"])
        }

        guard let content = String(data: data, encoding: .utf8) else {
            throw NSError(domain: "SubscriptionFetcher", code: 3, userInfo: [NSLocalizedDescriptionKey: "Конфигурация не в формате UTF-8"])
        }

        var updated = profile
        updated.cachedToml = content
        updated.updatedAt = Date().timeIntervalSince1970
        ProfileStore.shared.updateProfile(updated)
        return updated
    }
}
