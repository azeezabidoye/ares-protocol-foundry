// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library SpendingLib {
    uint256 internal constant WINDOW = 1 days;

    struct DailyTracker {
        uint256 windowStart;
        uint256 spent;
    }

    function maybeReset(DailyTracker storage tracker) internal {
        if (block.timestamp >= tracker.windowStart + WINDOW) {
            tracker.windowStart = block.timestamp;
            tracker.spent = 0;
        }
    }

    function recordSpend(DailyTracker storage tracker, uint256 amount, uint256 dailyLimit) internal {
        maybeReset(tracker);
        require(tracker.spent + amount <= dailyLimit, "SpendingLib: daily limit exceeded");
        tracker.spent += amount;
    }

    function wouldExceedDailyLimit(DailyTracker storage tracker, uint256 amount, uint256 dailyLimit)
        internal
        view
        returns (bool)
    {
        uint256 effective = (block.timestamp >= tracker.windowStart + WINDOW) ? 0 : tracker.spent;
        return effective + amount > dailyLimit;
    }
}
