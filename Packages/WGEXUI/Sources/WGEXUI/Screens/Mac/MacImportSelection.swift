// SPDX-License-Identifier: MIT

// No platform guard: the iPhone and iPad review list uses the same ticks (SPEC 10).
import WGEXCore

/// Ticks of the several-tunnels review list (SPEC 6.2, DEC-110 item 21). Every review that can be imported starts ticked;
/// one with errors is never ticked and cannot be. The unticked reviews are held by reference, so a recycled object
/// address can never untick a new review; `prune` drops the ones that left the list.
@MainActor
public struct MacImportSelection {
    private var unticked: [ImportReviewModel] = []

    public init() {}

    public func isTicked(_ review: ImportReviewModel) -> Bool {
        review.canImport && !unticked.contains { $0 === review }
    }

    /// Ticking a review with errors does nothing.
    public mutating func set(_ review: ImportReviewModel, ticked: Bool) {
        guard review.canImport else { return }
        unticked.removeAll { $0 === review }
        if !ticked {
            unticked.append(review)
        }
    }

    /// The reviews the Add button saves, in list order.
    public func ticked(in reviews: [ImportReviewModel]) -> [ImportReviewModel] {
        reviews.filter(isTicked)
    }

    /// "Add All" while every importable review is ticked, otherwise "Add" with the count.
    public func buttonTitle(in reviews: [ImportReviewModel]) -> String {
        let count = ticked(in: reviews).count
        return count == reviews.count(where: \.canImport) ? MacStrings.addAll : MacStrings.addCount(count)
    }

    public mutating func prune(to reviews: [ImportReviewModel]) {
        unticked.removeAll { review in !reviews.contains { $0 === review } }
    }

    /// The row's endpoint: the first server's address and port, or Unavailable.
    public static func endpoint(_ review: ImportReviewModel) -> String {
        review.profile.peers.first?.endpoint.map(EndpointText.format) ?? MacStrings.unavailable
    }
}
