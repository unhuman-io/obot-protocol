// Copyright 2024 Figure AI, Inc
#pragma once

#include <stdint.h>

#include <functional>

namespace figure {

/// @brief Parse the protocol messages.
/// https://figure-ai.atlassian.net/l/cp/QGFVFYL9
class ProtocolParser {
 public:
  constexpr static uint8_t kStartByte1 = 0xCA;
  constexpr static uint8_t kStartByte2 = 0xFE;
  constexpr static uint8_t kNumStartBytes = 2;
  constexpr static uint8_t kNumCrcBytes = 2;
  constexpr static uint8_t kNumFrameIdBytes = 2;
  constexpr static uint8_t kNumPayloadLenBytes = 1;
  constexpr static uint8_t kNumPrePayloadBytes = 4;
  constexpr static uint8_t kMaxFrameIds = 128;
  constexpr static uint16_t kMaxPacketSize = 256;
  using callback_t = std::function<void(const uint8_t*, uint16_t)>;

  /// @brief Constructor to parse the protocol messages from a DMA buffer.
  /// @param buffer Pointer to the DMA buffer.
  /// @param buffer_size Size of the DMA buffer.
  explicit ProtocolParser(const uint8_t* buffer, uint32_t buffer_size)
      : buffer_(buffer), buffer_size_(buffer_size) {}

  /// @brief Process all new elements in the buffer and call associated callbacks.
  /// @param latest_idx index to the latest element in the buffer.
  void process(const uint32_t latest_idx);

  /// @brief Register a callback to be called when a packet with the given frame_id is received.
  /// @param frame_id The frame_id to register the callback for.
  /// @param callback The callback to call when a packet with the given frame_id is received.
  void registerCallback(uint8_t frame_id, callback_t&& callback);

  /// @brief Generate a packet that corresponds to the protocol.
  /// @param buffer Pointer to the packet buffer.
  /// @param buffer_size Size of the packet buffer.
  /// @param frame_id The frame_id of the generated packet.
  /// @param gen_packet_size Size of the generated packet.
  /// @return Pointer to the generated packet.
  uint8_t* generatePacket(const uint8_t* buffer, const uint32_t buffer_size, const uint8_t frame_id,
                          uint8_t* gen_packet_size);

  /// @brief Generate a packet that corresponds to the protocol.
  /// @param dst_buf Pointer to the destination packet buffer.
  /// @param dst_buf_size Size of the destination packet buffer.
  /// @param src_buf Pointer to the source packet buffer.
  /// @param src_buf_size Size of the source packet buffer.
  /// @param frame_id The frame_id of the generated packet.
  /// @return Total size of generated packet
  size_t generatePacketNoCopy(uint8_t* dst_buf, const size_t dst_buf_size, const uint8_t* src_buf,
                              const size_t src_buf_size, uint8_t frame_id);

  /// @brief Process packet in given buffer
  /// @param buffer Pointer to the packet buffer
  /// @param buffer_size Size of the packet buffer
  /// @return true if a a valid frame is received. false if no
  bool processSingleFrame(const uint8_t* buffer, size_t buffer_size);
  struct ProtocolStats {
    uint32_t invalid_crc;          // CRC errors
    uint32_t invalid_idx;          // Invalid circular buffer index error
    uint32_t invalid_frame_id;     // Invalid frame id error
    uint32_t invalid_sync_bytes;   // Invalid sync byte error
    uint32_t packets_received;     // Number of packets received
    uint32_t non_zero_sync_bytes;  // Number of packets with non-zero sync bytes
  };

  /// @brief Get the stats of the protocol parser
  /// @return The stats of the protocol parser
  ProtocolStats getStats() const { return stats_; }

  /// @brief Clear the stats of the protocol parser
  void clearStats() { stats_ = {}; }

 private:
  const uint8_t* buffer_;          // Pointer to the DMA buffer.
  const uint32_t buffer_size_{0};  // Size of the DMA buffer.
  uint32_t head_{0};               // Index to keep track of where to begin parsing for a packet.
  uint32_t tail_{0};               // Index to keep track of where to end parsing for a packet.
  callback_t callbacks_[kMaxFrameIds];         // Callbacks to call when a packet is received.
  uint8_t packet_buffer_[kMaxPacketSize];      // Buffer to store the packet being parsed.
  uint8_t gen_packet_buffer_[kMaxPacketSize];  // Buffer to store the packet being generated.
  ProtocolStats stats_ = {};                   // Stats to keep track of the protocol counters
};

}  // namespace figure
