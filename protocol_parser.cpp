/**
 * Copyright 2024 Figure AI, Inc
 */

#include "protocol_parser.h"  // NOLINT

#include <cstring>

#include "crc.h"

namespace figure {

uint8_t* ProtocolParser::generatePacket(const uint8_t* buffer, const uint32_t buffer_size,
                                        const uint8_t frame_id, uint8_t* gen_packet_size) {
  // construct a packet with the given data bytes + 2 crc bytes + 2 start bytes + 1 frame id + 1
  // payload length
  memset(gen_packet_buffer_, 0, kMaxPacketSize);  // Clear the buffer
  *gen_packet_size = buffer_size + kNumPrePayloadBytes + kNumCrcBytes;
  gen_packet_buffer_[0] = kStartByte1;
  gen_packet_buffer_[1] = kStartByte2;
  gen_packet_buffer_[2] = frame_id;     // frame id
  gen_packet_buffer_[3] = buffer_size;  // payload length
  std::memcpy(gen_packet_buffer_ + kNumPrePayloadBytes, buffer, buffer_size);
  // Calculate the crc on the packet and overhead bytes
  uint16_t crc = crc16(gen_packet_buffer_, buffer_size + kNumPrePayloadBytes);
  gen_packet_buffer_[buffer_size + kNumPrePayloadBytes] = crc >> 8;        // NOLINT
  gen_packet_buffer_[buffer_size + kNumPrePayloadBytes + 1] = crc & 0xFF;  // NOLINT
  return &gen_packet_buffer_[0];
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
void ProtocolParser::process(const uint32_t latest_idx) {
  tail_ = (latest_idx + 1) % buffer_size_;
  if (head_ == tail_) {
    // No new data to process
    return;
  }
  // Calculate number of bytes to process
  int bytes_to_process = 0;
  if (latest_idx >= head_) {
    bytes_to_process = latest_idx - head_ + 1;
  } else {
    // Tail has wrapped around to the beginning of the buffer
    bytes_to_process = buffer_size_ - head_ + latest_idx + 1;
  }

  // Keep searching through local buffer until we've reached the end.
  while (bytes_to_process > 0) {
    int start_index = head_;
    // Convert tail to a flat index so it's easier to work with in the context of the
    // circular buffer.
    int end_index = tail_ < head_ ? buffer_size_ + tail_ : tail_;

    // Loop through buffer_ beginning at start_index and find the start of a packet
    for (int i = start_index; i < end_index; i++) {
      if (buffer_[i % buffer_size_] != kStartByte1) {
        // Continue searching for start byte
        if (i + 1 == end_index) {
          // Reached the end of the buffer without finding a start byte.
          // Discard any bytes that have been processed by setting the head_ to tail_.
          head_ = tail_;
          return;
        }
        continue;
      }

      // Check that the buffer contains enough bytes to check up to the payload length
      if (i + 3 > end_index) {
        // Buffer does not contain enough bytes to read the payload length.
        // Update the head_ and return.
        head_ = i;
        return;
      }

      // Check for second start byte
      if (buffer_[(i + 1) % buffer_size_] != kStartByte2) {
        // Incorrect second start byte
        // Continue to search through buffer for start byte from i+2
        head_ = i + 2;
        bytes_to_process -= 2;
        break;
      }

      // Found the start of a packet
      // Parse payload length
      int payload_length = buffer_[(i + 3) % buffer_size_];
      const int packet_size = payload_length + 6;

      // Check if the buffer contains the entire packet
      if ((i + packet_size) > end_index) {
        // Buffer does not contain the entire packet
        // Return and wait for more data
        head_ = i % buffer_size_;
        return;
      }

      // Copy the packet into the local buffer
      // This is required for the crc16 function
      if ((i % buffer_size_) < tail_) {
        // TODO(kyle-figure): Remove this to only copy into the local buffer if the packet wraps
        std::memcpy(packet_buffer_, buffer_ + (i % buffer_size_), packet_size);
      } else {
        // Packet wraps around. Copy the packet in two parts.
        std::memcpy(packet_buffer_, buffer_ + (i % buffer_size_),
                    buffer_size_ - (i % buffer_size_));
        std::memcpy(packet_buffer_ + (buffer_size_ - (i % buffer_size_)), buffer_,
                    packet_size - (buffer_size_ - (i % buffer_size_)));
      }

      // Now that the packet is in the local buffer, we can parse it normally without worrying about
      // the circular buffer indices.

      // Parse frame ID
      const int kFrameIdOffset = 2;
      uint8_t frame_id = packet_buffer_[kFrameIdOffset];

      const int kNumHeaderBytes = 4;
      int end_of_payload =
          payload_length + kNumHeaderBytes;  // One past the last byte of the payload

      // Parse the crc
      const int kCrcOffset = end_of_payload;
      uint16_t crc = (packet_buffer_[kCrcOffset] << 8) | packet_buffer_[kCrcOffset + 1];  // NOLINT

      // Check CRC
      if (crc16(packet_buffer_, payload_length + kNumHeaderBytes) != crc) {
        // CRC is incorrect
        // TODO(kyle-figure): Track this error
        // Update the head_ and break to start searching for the next packet
        start_index = i + 2;
        head_ = start_index % buffer_size_;
        bytes_to_process = end_index - start_index;
        break;
      }

      // Call the callback for the packet
      if (callbacks_[frame_id] != nullptr) {
        callbacks_[frame_id](&packet_buffer_[kNumHeaderBytes], payload_length);
      } else {
        // No callback registered for the packet
        // TODO(kyle-figure): Track this error as an invalid frame ID
      }

      // Update the head_ index
      start_index = i + packet_size;
      head_ = start_index % buffer_size_;
      bytes_to_process = end_index - start_index;
      break;
    }
  }
}

void ProtocolParser::registerCallback(uint8_t frame_id, callback_t&& callback) {
  callbacks_[frame_id] = callback;
}

}  // namespace figure
