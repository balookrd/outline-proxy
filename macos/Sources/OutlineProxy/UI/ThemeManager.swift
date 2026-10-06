import AppKit
import Foundation

/// Defines theme selection mode for the application.
public enum AppThemeMode: String, CaseIterable, Sendable {
    case system = "system"
    case light = "light"
    case dark = "dark"
}

/// Comprehensive Material 3 palette matching Android AppTheme.kt.
public struct ThemePalette: Sendable {
    public let isDark: Bool

    // Surfaces & Backgrounds
    public let windowBackground: NSColor
    public let headerCardBg: NSColor
    public let contentCardBg: NSColor
    public let cardBorder: NSColor

    // Typography
    public let primaryText: NSColor
    public let secondaryText: NSColor

    // Brand Assets
    public let mapTint: NSColor
    public let logoAsset: String
    public let ringAsset: String

    // Subtitle & Badges
    public let badgeBg: NSColor
    public let badgeText: NSColor
    public let chevronTint: NSColor

    // Quick Action Bubbles
    public let bubbleBg: NSColor
    public let bubbleIcon: NSColor
    public let bubbleText: NSColor

    // Action Row Buttons
    public let addServerBg: NSColor
    public let addServerBorder: NSColor
    public let addServerText: NSColor

    public let connectBg: NSColor
    public let connectText: NSColor
    public let disconnectBg: NSColor
    public let disconnectText: NSColor

    // Mode Selector
    public let tabSelectedBg: NSColor
    public let tabSelectedText: NSColor
    public let tabUnselectedBg: NSColor
    public let tabUnselectedBorder: NSColor
    public let tabUnselectedText: NSColor

    // Semantic Status
    public let statusGreen: NSColor
    public let statusAmber: NSColor
    public let statusGray: NSColor
}

/// Centralized Theme Manager providing live theme switching and Android-identical palettes.
public final class ThemeManager: @unchecked Sendable {
    public static let shared = ThemeManager()

    private let modeKey = "OutlineProxyThemeMode"
    public static let themeChangedNotification = Notification.Name("OutlineThemeChanged")

    private init() {}

    public var mode: AppThemeMode {
        get {
            if let raw = UserDefaults.standard.string(forKey: modeKey),
               let parsed = AppThemeMode(rawValue: raw) {
                return parsed
            }
            return .system
        }
        set {
            UserDefaults.standard.set(newValue.rawValue, forKey: modeKey)
            NotificationCenter.default.post(name: ThemeManager.themeChangedNotification, object: nil)
        }
    }

    public func isDark(for window: NSWindow?) -> Bool {
        switch mode {
        case .light:
            return false
        case .dark:
            return true
        case .system:
            if let w = window {
                return w.effectiveAppearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            }
            return NSApp.effectiveAppearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
        }
    }

    public func palette(for window: NSWindow?) -> ThemePalette {
        let dark = isDark(for: window)
        return dark ? darkPalette : lightPalette
    }

    public func toggle(for window: NSWindow?) {
        let currentlyDark = isDark(for: window)
        mode = currentlyDark ? .light : .dark
    }

    // MARK: - Dark Palette (OLED Material 3 — matches Android OutlineDarkColorScheme)
    public let darkPalette = ThemePalette(
        isDark: true,
        windowBackground: NSColor(red: 0x0E/255.0, green: 0x11/255.0, blue: 0x18/255.0, alpha: 1.0),
        headerCardBg: NSColor(red: 0x16/255.0, green: 0x1C/255.0, blue: 0x26/255.0, alpha: 1.0),
        contentCardBg: NSColor(red: 0x16/255.0, green: 0x1C/255.0, blue: 0x26/255.0, alpha: 1.0),
        cardBorder: NSColor(white: 1.0, alpha: 0.10),

        primaryText: NSColor.white,
        secondaryText: NSColor(red: 0x94/255.0, green: 0xA3/255.0, blue: 0xB8/255.0, alpha: 1.0),

        mapTint: NSColor(white: 1.0, alpha: 0.22),
        logoAsset: "brand_logo_dark",
        ringAsset: "brand_ring_dark",

        badgeBg: NSColor(red: 0x1E/255.0, green: 0x29/255.0, blue: 0x3B/255.0, alpha: 1.0),
        badgeText: NSColor(red: 0x93/255.0, green: 0xC5/255.0, blue: 0xFD/255.0, alpha: 1.0),
        chevronTint: NSColor(white: 0.65, alpha: 1.0),

        bubbleBg: NSColor(red: 0x20/255.0, green: 0x29/255.0, blue: 0x3A/255.0, alpha: 1.0),
        bubbleIcon: NSColor(red: 0x60/255.0, green: 0xA5/255.0, blue: 0xFA/255.0, alpha: 1.0),
        bubbleText: NSColor.white,

        addServerBg: NSColor(red: 0x16/255.0, green: 0x1C/255.0, blue: 0x26/255.0, alpha: 1.0),
        addServerBorder: NSColor(white: 1.0, alpha: 0.12),
        addServerText: NSColor.white,

        connectBg: NSColor(red: 0xC7/255.0, green: 0xD7/255.0, blue: 0xFD/255.0, alpha: 1.0),
        connectText: NSColor(red: 0x0F/255.0, green: 0x17/255.0, blue: 0x2A/255.0, alpha: 1.0),
        disconnectBg: NSColor(red: 0xEF/255.0, green: 0x44/255.0, blue: 0x44/255.0, alpha: 1.0),
        disconnectText: NSColor.white,

        tabSelectedBg: NSColor(red: 0x25/255.0, green: 0x63/255.0, blue: 0xEB/255.0, alpha: 1.0),
        tabSelectedText: NSColor.white,
        tabUnselectedBg: NSColor(red: 0x20/255.0, green: 0x29/255.0, blue: 0x3A/255.0, alpha: 1.0),
        tabUnselectedBorder: NSColor(white: 1.0, alpha: 0.10),
        tabUnselectedText: NSColor(white: 0.75, alpha: 1.0),

        statusGreen: NSColor(red: 0x22/255.0, green: 0xC5/255.0, blue: 0x5E/255.0, alpha: 1.0),
        statusAmber: NSColor(red: 0xF5/255.0, green: 0x9E/255.0, blue: 0x0B/255.0, alpha: 1.0),
        statusGray: NSColor(red: 0x94/255.0, green: 0xA3/255.0, blue: 0xB8/255.0, alpha: 1.0)
    )

    // MARK: - Light Palette (Clean Material 3 — matches Android OutlineLightColorScheme)
    public let lightPalette = ThemePalette(
        isDark: false,
        windowBackground: NSColor(red: 0xF8/255.0, green: 0xFA/255.0, blue: 0xFC/255.0, alpha: 1.0),
        headerCardBg: NSColor.white,
        contentCardBg: NSColor(red: 0xED/255.0, green: 0xF2/255.0, blue: 0xF7/255.0, alpha: 1.0),
        cardBorder: NSColor(red: 0xCB/255.0, green: 0xD5/255.0, blue: 0xE1/255.0, alpha: 1.0),

        primaryText: NSColor(red: 0x0F/255.0, green: 0x17/255.0, blue: 0x2A/255.0, alpha: 1.0),
        secondaryText: NSColor(red: 0x47/255.0, green: 0x55/255.0, blue: 0x69/255.0, alpha: 1.0),

        mapTint: NSColor(red: 0x0F/255.0, green: 0x17/255.0, blue: 0x2A/255.0, alpha: 0.12),
        logoAsset: "brand_logo_light",
        ringAsset: "brand_ring_light",

        badgeBg: NSColor(red: 0xDB/255.0, green: 0xE6/255.0, blue: 0xFE/255.0, alpha: 1.0),
        badgeText: NSColor(red: 0x1E/255.0, green: 0x3A/255.0, blue: 0x8A/255.0, alpha: 1.0),
        chevronTint: NSColor(red: 0x64/255.0, green: 0x74/255.0, blue: 0x8B/255.0, alpha: 1.0),

        bubbleBg: NSColor(red: 0xDB/255.0, green: 0xE6/255.0, blue: 0xFE/255.0, alpha: 1.0),
        bubbleIcon: NSColor(red: 0x1E/255.0, green: 0x5E/255.0, blue: 0xE8/255.0, alpha: 1.0),
        bubbleText: NSColor(red: 0x0F/255.0, green: 0x17/255.0, blue: 0x2A/255.0, alpha: 1.0),

        addServerBg: NSColor.white,
        addServerBorder: NSColor(red: 0xCB/255.0, green: 0xD5/255.0, blue: 0xE1/255.0, alpha: 1.0),
        addServerText: NSColor(red: 0x0F/255.0, green: 0x17/255.0, blue: 0x2A/255.0, alpha: 1.0),

        connectBg: NSColor(red: 0x1E/255.0, green: 0x5E/255.0, blue: 0xE8/255.0, alpha: 1.0),
        connectText: NSColor.white,
        disconnectBg: NSColor(red: 0xDC/255.0, green: 0x26/255.0, blue: 0x26/255.0, alpha: 1.0),
        disconnectText: NSColor.white,

        tabSelectedBg: NSColor(red: 0x1E/255.0, green: 0x5E/255.0, blue: 0xE8/255.0, alpha: 1.0),
        tabSelectedText: NSColor.white,
        tabUnselectedBg: NSColor.white,
        tabUnselectedBorder: NSColor(red: 0xCB/255.0, green: 0xD5/255.0, blue: 0xE1/255.0, alpha: 1.0),
        tabUnselectedText: NSColor(red: 0x47/255.0, green: 0x55/255.0, blue: 0x69/255.0, alpha: 1.0),

        statusGreen: NSColor(red: 0x05/255.0, green: 0x96/255.0, blue: 0x69/255.0, alpha: 1.0),
        statusAmber: NSColor(red: 0xD9/255.0, green: 0xB7/255.0, blue: 0x06/255.0, alpha: 1.0),
        statusGray: NSColor(red: 0x64/255.0, green: 0x74/255.0, blue: 0x8B/255.0, alpha: 1.0)
    )
}
