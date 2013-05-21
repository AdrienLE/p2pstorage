/* Copyright (c) 2010 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// Author: Christopher M. Kohlhoff (chris at kohlhoff dot com)

#ifndef MAIDSAFE_TRANSPORT_RUDP_SLIDING_WINDOW_H_
#define MAIDSAFE_TRANSPORT_RUDP_SLIDING_WINDOW_H_

#include <cassert>
#include <deque>

#include "boost/cstdint.hpp"
#include "maidsafe/common/utils.h"

#include "maidsafe/transport/rudp_parameters.h"

namespace maidsafe {

namespace transport {

template <typename T>
class RudpSlidingWindow {
 public:
  // The maximum possible sequence number. When reached, sequence numbers are
  // wrapped around to start from 0.
  enum { kMaxSequenceNumber = 0x7fffffff };

  // Construct to start with a random sequence number.
  RudpSlidingWindow()
      : items_(), maximum_size_(0), begin_(0), end_(0) {
    Reset(GenerateSequenceNumber());
  }

  // Construct to start with a specified sequence number.
  explicit RudpSlidingWindow(boost::uint32_t initial_sequence_number)
      : items_(),
        maximum_size_(RudpParameters::default_window_size),
        begin_(initial_sequence_number),
        end_(initial_sequence_number) {}

  // Reset to empty starting with the specified sequence number.
  void Reset(boost::uint32_t initial_sequence_number) {
    assert(initial_sequence_number <= kMaxSequenceNumber);
    maximum_size_ = RudpParameters::default_window_size;
    begin_ = end_ = initial_sequence_number;
    items_.clear();
  }

  // Get the sequence number of the first item in window.
  boost::uint32_t Begin() const {
    return begin_;
  }

  // Get the one-past-the-end sequence number.
  boost::uint32_t End() const {
    return end_;
  }

  // Determine whether a sequence number is in the window.
  bool Contains(boost::uint32_t n) const {
    return IsInRange(begin_, end_, n);
  }

  // Determine whether a sequence number is within one window size past the
  // end. This is used to filter out packets with non-sensical sequence numbers.
  bool IsComingSoon(boost::uint32_t n) const {
    boost::uint32_t begin = end_;
    boost::uint32_t end =
        (begin + RudpParameters::maximum_window_size) %
            (static_cast<boost::uint32_t>(kMaxSequenceNumber) + 1);
    return IsInRange(begin, end, n);
  }

  // Get the maximum size of the window.
  size_t MaximumSize() const {
    return maximum_size_;
  }

  // Set the maximum size of the window.
  void SetMaximumSize(size_t size) {
    maximum_size_ = size < RudpParameters::maximum_window_size
                    ? size : RudpParameters::maximum_window_size;
  }

  // Get the current size of the window.
  size_t Size() const {
    return items_.size();
  }

  // Get whether the window is empty.
  bool IsEmpty() const {
    return items_.empty();
  }

  // Get whether the window is full.
  bool IsFull() const {
    return items_.size() >= maximum_size_;
  }

  // Add a new item to the end.
  // Precondition: !IsFull().
  boost::uint32_t Append() {
    assert(!IsFull());
    items_.push_back(T());
    boost::uint32_t n = end_;
    end_ = Next(end_);
    return n;
  }

  // Remove the first item from the window.
  // Precondition: !IsEmpty().
  void Remove() {
    assert(!IsEmpty());
    items_.erase(items_.begin());
    begin_ = Next(begin_);
  }

  // Get the item with the specified sequence number.
  // Precondition: Contains(n).
  T &operator[](boost::uint32_t n) {
    return items_[SequenceNumberToIndex(n)];
  }

  // Get the item with the specified sequence number.
  // Precondition: Contains(n).
  const T &operator[](boost::uint32_t n) const {
    return items_[SequenceNumberToIndex(n)];
  }

  // Get the element at the front of the window.
  // Precondition: !IsEmpty().
  T &Front() {
    return items_.front();
  }

  // Get the element at the front of the window.
  // Precondition: !IsEmpty().
  const T &Front() const {
    return items_.front();
  }

  // Get the element at the back of the window.
  // Precondition: !IsEmpty().
  T &Back() {
    assert(!IsEmpty());
    return items_.front();
  }

  // Get the element at the back of the window.
  // Precondition: !IsEmpty().
  const T &Back() const {
    assert(!IsEmpty());
    return items_.back();
  }

  // Get the sequence number that follows a given number.
  static boost::uint32_t Next(boost::uint32_t n) {
    return (n == kMaxSequenceNumber) ? 0 : n + 1;
  }

 private:
  // Disallow copying and assignment.
  RudpSlidingWindow(const RudpSlidingWindow&);
  RudpSlidingWindow &operator=(const RudpSlidingWindow&);

  // Helper function to convert a sequence number into an index in the window.
  size_t SequenceNumberToIndex(boost::uint32_t n) const {
    assert(Contains(n));
    if (begin_ <= end_)
      return n - begin_;
    else if (n < end_)
      return kMaxSequenceNumber - begin_ + n + 1;
    else
      return n - begin_;
  }

  // Helper function to generate an initial sequence number.
  static boost::uint32_t GenerateSequenceNumber() {
    boost::uint32_t seqnum = 0;
    while (seqnum == 0)
      seqnum = (RandomUint32() & 0x7fffffff);
    return seqnum;
  }

  // Helper function to determine if a sequence number is in a given range.
  static bool IsInRange(boost::uint32_t begin,
                        boost::uint32_t end,
                        boost::uint32_t n) {
    if (begin <= end)
      return (begin <= n) && (n < end);
    else
      return (n < end) || ((n >= begin) && (n <= kMaxSequenceNumber));
  }

  // The items in the window.
  std::deque<T> items_;

  // The maximum number of items allowed in the window.
  size_t maximum_size_;

  // The sequence number of the first item in window.
  boost::uint32_t begin_;

  // The one-past-the-end sequence number for the window. Will be used as the
  // sequence number of the next item added.
  boost::uint32_t end_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_RUDP_SLIDING_WINDOW_H_
