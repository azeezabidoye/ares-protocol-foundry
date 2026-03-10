// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title SpendingLib
/// @notice Pure/view helpers for enforcing per-transaction and rolling daily
///         spending limits.  State management is left to the caller.
library SpendingLib {
    // ─────────────────────────────────────────────────────────────────────────
    // Constants
    // ─────────────────────────────────────────────────────────────────────────

    uint256 internal constant WINDOW = 1 days;

    // ─────────────────────────────────────────────────────────────────────────
    // Structs
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Caller stores one of these in contract storage.
    struct DailyTracker {
        uint256 windowStart;  // Timestamp when the current window opened
        uint256 spent;        // Total value spent in the current window
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Functions
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Reset the tracker if the 24-hour window has elapsed.
    /// @param  tracker   Storage reference to the caller's DailyTracker
    function maybeReset(DailyTracker storage tracker) internal {
        if (block.timestamp >= tracker.windowStart + WINDOW) {
            tracker.windowStart = block.timestamp;
            tracker.spent = 0;
        }
    }

    /// @notice Record a spend, reverting if it would breach the daily limit.
    /// @param  tracker    Storage reference
    /// @param  amount     Amount being spent now
    /// @param  dailyLimit Maximum allowed per rolling 24-hour window
    function recordSpend(
        DailyTracker storage tracker,
        uint256 amount,
        uint256 dailyLimit
    ) internal {
        maybeReset(tracker);
        require(
            tracker.spent + amount <= dailyLimit,
            "SpendingLib: daily limit exceeded"
        );
        tracker.spent += amount;
    }

    /// @notice View-only check: would this spend breach the limit right now?
    function wouldExceedDailyLimit(
        DailyTracker storage tracker,
        uint256 amount,
        uint256 dailyLimit
    ) internal view returns (bool) {
        uint256 effective = (block.timestamp >= tracker.windowStart + WINDOW)
            ? 0
            : tracker.spent;
        return effective + amount > dailyLimit;
    }
}
