package com.saoif.marketprobe;

import android.content.Context;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.TreeMap;

/**
 * Passive TCP decoder for the observed SAOIF v3.2.4 market response.
 * Does not transmit requests, decrypt payloads, or modify the game.
 * Observed response: LE u16 frame length, LE u16 opcode 0x7198,
 * LE u16 listing count, 69 bytes per listing.
 * Field labels are provisional until validated against game UI.
 */
final class MarketDecoder {
    private static final int OPCODE_MARKET = 0x7198;
    private static final int SERVER_PORT = 31061;
    private static final int RECORD_SIZE = 69;
    private static final int MAX_STREAM_BUFFER = 1024 * 1024;
    private final File csv;
    private final Map<String, Stream> streams = new HashMap<>();
    private final HashSet<String> seenListings = new HashSet<>();
    private final HashSet<Long> items = new HashSet<>();
    private long rows;
    private long responses;
    private String error = "";

    MarketDecoder(Context ctx) {
        csv = new File(ctx.getFilesDir(), "market_listings.csv");
        try (FileOutputStream out = new FileOutputStream(csv, false)) {
            out.write("captured_at_utc,item_id,listing_id,price,quantity\n".getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            error = "Cannot create market CSV: " + e.getMessage();
        }
    }

    private static int u16le(byte[] d, int p) {
        return (d[p] & 255) | ((d[p + 1] & 255) << 8);
    }
    private static long u32le(byte[] d, int p) {
        return ((long)d[p] & 255) |
               (((long)d[p + 1] & 255) << 8) |
               (((long)d[p + 2] & 255) << 16) |
               (((long)d[p + 3] & 255) << 24);
    }
    private static long u32be(byte[] d, int p) {
        return (((long)d[p] & 255) << 24) |
               (((long)d[p + 1] & 255) << 16) |
               (((long)d[p + 2] & 255) << 8) |
               ((long)d[p + 3] & 255);
    }

    synchronized void consumePcapRecord(byte[] data, int count) {
        // 16-byte libpcap record header; DLT_RAW IPv4 captured by PCAPdroid.
        if (count < 16 + 20) return;
        int incl = (int)u32le(data, 8);
        if (incl < 20 || incl + 16 > count) return;
        int ip = 16;
        if ((data[ip] & 0xf0) != 0x40) return;
        int ipHeader = (data[ip] & 0x0f) * 4;
        if (ipHeader < 20 || ip + ipHeader + 20 > count) return;
        if ((data[ip + 9] & 255) != 6) return;
        int frag = ((data[ip + 6] & 31) << 8) | (data[ip + 7] & 255);
        if (frag != 0) return;
        int tcp = ip + ipHeader;
        int sourcePort = ((data[tcp] & 255) << 8) | (data[tcp + 1] & 255);
        if (sourcePort != SERVER_PORT) return;
        int destinationPort = ((data[tcp + 2] & 255) << 8) | (data[tcp + 3] & 255);
        int tcpHeader = ((data[tcp + 12] & 0xf0) >> 4) * 4;
        int totalIp = ((data[ip + 2] & 255) << 8) | (data[ip + 3] & 255);
        int start = tcp + tcpHeader;
        int end = Math.min(count, Math.min(16 + incl, ip + totalIp));
        if (tcpHeader < 20 || start >= end) return;
        long sequence = u32be(data, tcp + 4);
        long src = u32be(data, ip + 12);
        long dst = u32be(data, ip + 16);
        String key = src + "/" + dst + "/" + destinationPort;
        Stream stream = streams.get(key);
        if (stream == null) {
            stream = new Stream();
            streams.put(key, stream);
        }
        byte[] payload = Arrays.copyOfRange(data, start, end);
        stream.accept(sequence, payload);
    }

    synchronized long getRows() { return rows; }
    synchronized int getItemCount() { return items.size(); }
    synchronized long getResponseCount() { return responses; }
    synchronized String getError() { return error; }

    private void readMessage(byte[] d, int at, int frameLength) {
        if (frameLength < 4 || u16le(d, at + 2) != OPCODE_MARKET) return;
        int n = u16le(d, at + 4);
        if (frameLength != 4 + n * RECORD_SIZE || n == 0) return;
        StringBuilder sb = new StringBuilder();
        String timestamp = Instant.now().toString();
        int newRows = 0;
        for (int j = 0; j < n; j++) {
            int p = at + 6 + j * RECORD_SIZE;
            long listing = u32le(d, p);
            long item = u32le(d, p + 4);
            long price = u32le(d, p + 61);
            long quantity = u32le(d, p + 65);
            if (listing == 0 || item == 0 || price == 0 || quantity == 0) continue;
            String key = item + ":" + listing;
            if (!seenListings.add(key)) continue;
            items.add(item);
            sb.append(timestamp).append(',').append(item).append(',').append(listing)
              .append(',').append(price).append(',').append(quantity).append('\n');
            newRows++;
        }
        if (newRows > 0) {
            try (FileOutputStream out = new FileOutputStream(csv, true)) {
                out.write(sb.toString().getBytes(StandardCharsets.UTF_8));
                rows += newRows;
            } catch (Exception e) {
                error = "CSV write: " + e.getMessage();
            }
        }
        responses++;
    }

    private final class Stream {
        private long expected = -1L;
        private final TreeMap<Long, byte[]> queued = new TreeMap<>();
        private final ByteArrayOutputStream unread = new ByteArrayOutputStream();
        void accept(long seq, byte[] payload) {
            if (expected < 0) expected = seq;
            if (seq > expected) {
                queued.putIfAbsent(seq, payload);
                if (queued.size() > 500) {
                    queued.clear();
                    error = "TCP reorder window too large";
                }
                return;
            }
            if (seq + payload.length <= expected) return;
            int skip = (int)Math.max(0, expected - seq);
            append(payload, skip, payload.length - skip);
            expected = seq + payload.length;
            while (!queued.isEmpty()) {
                Map.Entry<Long, byte[]> next = queued.firstEntry();
                if (next.getKey() > expected) break;
                queued.pollFirstEntry();
                long nextSequence = next.getKey();
                byte[] b = next.getValue();
                if (nextSequence + b.length > expected) {
                    int s = (int)(expected - nextSequence);
                    append(b, s, b.length - s);
                    expected = nextSequence + b.length;
                }
            }
        }
        private void append(byte[] data, int off, int length) {
            if (length <= 0) return;
            unread.write(data, off, length);
            if (unread.size() > MAX_STREAM_BUFFER) {
                unread.reset();
                error = "Stream buffer exceeded safety limit";
                return;
            }
            byte[] d = unread.toByteArray();
            int p = 0;
            while (p + 4 <= d.length) {
                int frameLen = u16le(d, p);
                if (frameLen < 2) {
                    unread.reset();
                    error = "Unexpected TCP frame format";
                    return;
                }
                if (p + 2 + frameLen > d.length) break;
                readMessage(d, p, frameLen);
                p += frameLen + 2;
            }
            if (p > 0) {
                unread.reset();
                unread.write(d, p, d.length - p);
            }
        }
    }
}
