import Foundation

/// Fetches config subscriptions from remote HTTPS URLs.
public enum SubscriptionFetcher {

    public static let maxResponseBytes = 512 * 1024 // 512 KiB max config size

    public static func updateSubscription(_ profile: ServerProfile) async throws -> ServerProfile {
        guard let url = URL(string: profile.configUrl),
              let scheme = url.scheme?.lowercased(),
              scheme == "https" else {
            throw NSError(domain: "SubscriptionFetcher", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "Некорректный URL подписки: разрешён только защищённый протокол https://"
            ])
        }

        var request = URLRequest(url: url)
        request.timeoutInterval = 15
        request.setValue("OutlineProxy-macOS/1.0", forHTTPHeaderField: "User-Agent")

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) else {
            let code = (response as? HTTPURLResponse)?.statusCode ?? 0
            throw NSError(domain: "SubscriptionFetcher", code: 2, userInfo: [
                NSLocalizedDescriptionKey: "Ошибка загрузки подписки: статус HTTP \(code)"
            ])
        }

        guard data.count <= maxResponseBytes else {
            throw NSError(domain: "SubscriptionFetcher", code: 4, userInfo: [
                NSLocalizedDescriptionKey: "Размер файла конфигурации превышает лимит \(maxResponseBytes / 1024) КБ"
            ])
        }

        guard let content = String(data: data, encoding: .utf8) else {
            throw NSError(domain: "SubscriptionFetcher", code: 3, userInfo: [
                NSLocalizedDescriptionKey: "Конфигурация не в формате UTF-8"
            ])
        }

        let trimmed = content.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw NSError(domain: "SubscriptionFetcher", code: 5, userInfo: [
                NSLocalizedDescriptionKey: "Получен пустой ответ конфигурации"
            ])
        }

        let lower = trimmed.lowercased()
        if lower.contains("<!doctype html") || lower.contains("<html") || lower.hasPrefix("<?xml") {
            throw NSError(domain: "SubscriptionFetcher", code: 6, userInfo: [
                NSLocalizedDescriptionKey: "Ответ сервера содержит HTML/XML вместо TOML конфигурации"
            ])
        }

        guard trimmed.contains("=") || trimmed.contains("[") else {
            throw NSError(domain: "SubscriptionFetcher", code: 7, userInfo: [
                NSLocalizedDescriptionKey: "Невалидный формат TOML: отсутствуют секции или пары ключ-значение"
            ])
        }

        var updated = profile
        updated.cachedToml = content
        updated.updatedAt = Date().timeIntervalSince1970
        ProfileStore.shared.updateProfile(updated)
        return updated
    }
}
