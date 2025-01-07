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

size_t ProtocolParser::generatePacketNoCopy(uint8_t* dst_buf, const size_t dst_buf_size,
                                            const uint8_t* src_buf, const size_t src_buf_size,
                                            uint8_t frame_id) {
  // construct a packet with the given data bytes + 2 crc bytes + 2 start bytes + 1 frame id + 1
  // payload length
  size_t generated_size = src_buf_size + kNumPrePayloadBytes + kNumCrcBytes;

  if (generated_size > dst_buf_size) {
    // skip generating packet since it won't fit in destination buffer
    return 0U;
  }

  dst_buf[0] = kStartByte1;
  dst_buf[1] = kStartByte2;
  dst_buf[2] = frame_id;      // frame id
  dst_buf[3] = src_buf_size;  // payload length
  std::memcpy(dst_buf + kNumPrePayloadBytes, src_buf, src_buf_size);
  // Calculate the crc on the packet and overhead bytes
  uint16_t crc = lib::crc16(dst_buf, src_buf_size + kNumPrePayloadBytes);
  dst_buf[src_buf_size + kNumPrePayloadBytes] = crc >> 8;        // NOLINT
  dst_buf[src_buf_size + kNumPrePayloadBytes + 1] = crc & 0xFF;  // NOLINT

  return generated_size;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
void ProtocolParser::process(const uint32_t latest_idx) {
  // Check that the index is within the buffer size
  if (latest_idx < 0 || latest_idx >= buffer_size_) {
    stats_.invalid_idx++;
    return;
  }
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
        if (buffer_[i % buffer_size_] != 0x00) {
          stats_.invalid_sync_bytes++;
        }
        if (i + 1 == end_index) {
          // Reached the end of the buffer without finding a start byte.
          // Discard any bytes that have been processed by setting the head_ to tail_.
          head_ = tail_ % buffer_size_;
          return;
        }

        // Continue searching for start byte
        continue;
      }

      // Check that the buffer contains enough bytes to check up to the payload length
      if (i + 3 > end_index) {
        // Buffer does not contain enough bytes to read the payload length.
        // Update the head_ and return.
        head_ = i % buffer_size_;
        return;
      }

      // Check for second start byte
      if (buffer_[(i + 1) % buffer_size_] != kStartByte2) {
        // Incorrect second start byte
        // Continue to search through buffer for start byte from i+2
        head_ = (i + 2) % buffer_size_;
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
      for (int j = 0; j < packet_size; j++) {
        packet_buffer_[j] = buffer_[(i + j) % buffer_size_];
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
        // Update the head_ and break to start searching for the next packet
        stats_.invalid_crc++;
        start_index = i + 2;
        head_ = start_index % buffer_size_;
        bytes_to_process = end_index - start_index;
        break;
      }

      // Call the callback for the packet
      if (callbacks_[frame_id] != nullptr) {
        stats_.packets_received++;
        callbacks_[frame_id](&packet_buffer_[kNumHeaderBytes], payload_length);
      } else {
        // No callback registered for the packet
        stats_.invalid_frame_id++;
      }

      // Update the head_ index
      start_index = i + packet_size;
      head_ = start_index % buffer_size_;
      bytes_to_process = end_index - start_index;
      break;
    }
  }
}

bool ProtocolParser::processSingleFrame(const uint8_t* buffer, size_t buffer_size) {
  const size_t kNumHeaderBytes = 4U;
  const size_t kNumPayloadLenOffset = 3U;
  const size_t kFrameIdOffset = 2U;
  const size_t kCrcBytes = 2U;

  // No enough bytes for a complete frame. drop frame
  if (buffer_size < (kNumHeaderBytes + kCrcBytes)) {
    return false;
  }

  // Search for start bytes
  for (size_t start_index = 0U; start_index < (buffer_size - kNumHeaderBytes - kCrcBytes);
       start_index++) {
    if ((buffer[start_index] != kStartByte1) && (buffer[start_index] != 0x00)) {
      stats_.invalid_sync_bytes++;
      continue;
    }
    if ((buffer[start_index] == kStartByte1) && (buffer[start_index + 1U] == kStartByte2)) {
      const uint8_t* packet_buffer = &buffer[start_index];
      size_t payload_length = packet_buffer[kNumPayloadLenOffset];

      if ((payload_length + kNumHeaderBytes + kCrcBytes) > (buffer_size - start_index)) {
        return false;
      }

      const size_t kCrcOffset = payload_length + kNumHeaderBytes;
      uint16_t calculated_crc = lib::crc16(packet_buffer, payload_length + kNumHeaderBytes);
      uint16_t received_crc =
          ((uint16_t)packet_buffer[kCrcOffset] << 8) | packet_buffer[kCrcOffset + 1U];

      if (calculated_crc == received_crc) {
        uint8_t frame_id = packet_buffer[kFrameIdOffset];
        if ((frame_id < kMaxFrameIds) && (callbacks_[frame_id] != nullptr)) {
          stats_.packets_received++;
          callbacks_[frame_id](&packet_buffer[kNumHeaderBytes], payload_length);
          return true;
        } else {
          // No callback registered for the packet
          stats_.invalid_frame_id++;
        }
      } else {
        stats_.invalid_crc++;
      }
      break;
    }
  }
  return false;
}

void ProtocolParser::registerCallback(uint8_t frame_id, callback_t&& callback) {
  callbacks_[frame_id] = callback;
}

}  // namespace figure
